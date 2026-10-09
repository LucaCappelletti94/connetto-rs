package dev.connetto.peer

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.SoftApConfiguration
import android.net.wifi.WifiManager
import android.net.wifi.WifiNetworkSpecifier
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import java.net.Inet4Address

/**
 * The local-only hotspot the peer link hosts, and the peer hotspots it joins.
 *
 * All state stands behind [lock]; the [JvmStatic]s are the JNI surface the
 * client drives. The host side answers with [HOST_PENDING] until the system
 * has started the hotspot, at which point the details stand ready for
 * `hostSsid`, `hostPassphrase` and `hostSecurity`. The join side answers with
 * [JOIN_PENDING] until the joined network's link properties stand ready, at
 * which point the joined address, prefix and gateway stand ready.
 *
 * The host callbacks are the API 34 signatures, whose `onStarted` hands the
 * configured reservation; the API 33 signatures the platform removed, so
 * hosting stands on 34 and later only.
 */
class HotspotPlugin {
    companion object {
        private const val HOST_IDLE = 0
        private const val HOST_PENDING = 1
        private const val HOST_STARTED = 2
        private const val HOST_FAILED = 3
        private const val HOST_STOPPED = 4

        private const val JOIN_IDLE = 0
        private const val JOIN_PENDING = 1
        private const val JOIN_AVAILABLE = 2
        private const val JOIN_UNAVAILABLE = 3
        private const val JOIN_LOST = 4

        private const val SECURITY_WPA2 = 0
        private const val SECURITY_WPA3 = 1

        private const val PERMISSION_REQUEST = 1001

        private val lock = Any()
        private val handler = Handler(Looper.getMainLooper())

        private var hostState: Int = HOST_IDLE
        private var hostSsid: String? = null
        private var hostPassphrase: String? = null
        private var hostSecurity: Int = SECURITY_WPA2
        private var hostFailure: String? = null
        // The host request each callback stands tagged with, so a stale
        // callback is told from the current one.
        private var hostRequest: Long = 0
        private var reservation: WifiManager.LocalOnlyHotspotReservation? = null

        private var joinState: Int = JOIN_IDLE
        private var joinAddress: String? = null
        private var joinPrefix: Int = 0
        private var joinGateway: String? = null
        private var joinNetwork: Network? = null
        private var joinCallback: ConnectivityManager.NetworkCallback? = null

        // The application's context, from its cache, else from the
        // framework's own accessor, which the SDK's stubs keep hidden.
        private var cachedContext: Context? = null

        @JvmStatic
        fun startHost() {
            synchronized(lock) {
                // A stale reservation from an abandoned request would hold the
                // hotspot, so it closes before the new request goes out.
                reservation?.close()
                reservation = null
                hostSsid = null
                hostPassphrase = null
                hostFailure = null
                val context = context() ?: return
                if (Build.VERSION.SDK_INT >= 33 &&
                    context.checkSelfPermission(Manifest.permission.NEARBY_WIFI_DEVICES) !=
                    PackageManager.PERMISSION_GRANTED
                ) {
                    hostState = HOST_FAILED
                    hostFailure = Manifest.permission.NEARBY_WIFI_DEVICES
                    return
                }
                hostState = HOST_PENDING
                val wifi = context.getSystemService(Context.WIFI_SERVICE) as WifiManager
                hostRequest += 1
                val request = hostRequest
                val callback = object : WifiManager.LocalOnlyHotspotCallback() {
                    @Suppress("DEPRECATION")
                    override fun onStarted(started: WifiManager.LocalOnlyHotspotReservation) {
                        synchronized(lock) {
                            // The request stands stopped or replaced, so
                            // the hotspot it started goes with it.
                            if (request != hostRequest || hostState != HOST_PENDING) {
                                started.close()
                                return
                            }
                            reservation = started
                            val config =
                                runCatching { started.getSoftApConfiguration() }
                                    .getOrNull()
                            if (config == null) {
                                hostState = HOST_FAILED
                                hostFailure = "0"
                                return
                            }
                            hostSsid =
                                config.wifiSsid
                                    ?.bytes
                                    ?.let { String(it, Charsets.UTF_8) }
                                    ?: config.ssid
                            hostPassphrase = config.passphrase
                            hostSecurity =
                                if (config.securityType ==
                                    SoftApConfiguration.SECURITY_TYPE_WPA2_PSK
                                ) {
                                    SECURITY_WPA2
                                } else {
                                    SECURITY_WPA3
                                }
                            hostState = HOST_STARTED
                        }
                    }

                    override fun onStopped() {
                        synchronized(lock) {
                            if (request != hostRequest) return
                            if (hostState == HOST_STARTED) {
                                hostState = HOST_STOPPED
                            }
                        }
                    }

                    override fun onFailed(status: Int) {
                        synchronized(lock) {
                            if (request != hostRequest) return
                            if (hostState != HOST_PENDING) return
                            hostState = HOST_FAILED
                            hostFailure = when (status) {
                                // The client's Incompatible and NoChannel
                                // rows, in the platform's codes.
                                WifiManager.LocalOnlyHotspotCallback.ERROR_INCOMPATIBLE_MODE ->
                                    "1"

                                WifiManager.LocalOnlyHotspotCallback.ERROR_NO_CHANNEL -> "2"

                                else -> "0"
                            }
                        }
                    }
                }
                try {
                    // The API 34 request stands the reservation in its
                    // `onStarted`, not in the call's answer.
                    wifi.startLocalOnlyHotspot(callback, handler)
                } catch (e: SecurityException) {
                    hostState = HOST_FAILED
                    hostFailure = Manifest.permission.NEARBY_WIFI_DEVICES
                }
            }
        }

        @JvmStatic
        fun stopHost() {
            synchronized(lock) {
                reservation?.close()
                reservation = null
                hostState = HOST_IDLE
            }
        }

        @JvmStatic
        fun hostState(): Int = synchronized(lock) { hostState }

        @JvmStatic
        fun hostSsid(): String? = synchronized(lock) { hostSsid }

        @JvmStatic
        fun hostPassphrase(): String? = synchronized(lock) { hostPassphrase }

        @JvmStatic
        fun hostSecurity(): Int = synchronized(lock) { hostSecurity }

        @JvmStatic
        fun hostFailure(): String? = synchronized(lock) { hostFailure }

        @JvmStatic
        fun join(ssid: String, passphrase: String, security: Int, timeoutMs: Long) {
            synchronized(lock) {
                leaveLocked()
                val context = context() ?: return
                val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE)
                    as ConnectivityManager
                val specifierBuilder = WifiNetworkSpecifier.Builder().setSsid(ssid)
                if (security == SECURITY_WPA3) {
                    specifierBuilder.setWpa3Passphrase(passphrase)
                } else {
                    specifierBuilder.setWpa2Passphrase(passphrase)
                }
                val request = NetworkRequest.Builder()
                    .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                    .setNetworkSpecifier(specifierBuilder.build())
                    .build()
                val callback = object : ConnectivityManager.NetworkCallback() {
                    override fun onAvailable(network: Network) {
                        synchronized(lock) {
                            if (joinState != JOIN_PENDING) return
                            joinNetwork = network
                        }
                    }

                    // The joined network's address, prefix and gateway stand
                    // in the link properties the platform reports on their
                    // assignment.
                    override fun onLinkPropertiesChanged(
                        network: Network,
                        linkProperties: LinkProperties
                    ) {
                        synchronized(lock) {
                            if (joinState != JOIN_PENDING || network != joinNetwork) return
                            fillInFrom(linkProperties)
                        }
                    }

                    override fun onUnavailable() {
                        synchronized(lock) {
                            if (joinState != JOIN_PENDING) return
                            joinState = JOIN_UNAVAILABLE
                            // The platform dropped the request, so the
                            // callback stands unregistered.
                            joinCallback = null
                            joinNetwork = null
                        }
                    }

                    override fun onLost(network: Network) {
                        synchronized(lock) {
                            if (joinState == JOIN_PENDING || joinState == JOIN_AVAILABLE) {
                                joinState = JOIN_LOST
                            }
                            unregisterLocked()
                        }
                    }
                }
                try {
                    cm.requestNetwork(request, callback, timeoutMs.toInt())
                    // The request stands registered, so a later leave or
                    // join unregisters it.
                    joinCallback = callback
                    joinState = JOIN_PENDING
                } catch (e: Exception) {
                    joinState = JOIN_UNAVAILABLE
                }
            }
        }

        @JvmStatic
        fun leave() {
            synchronized(lock) {
                leaveLocked()
            }
        }

        @JvmStatic
        fun joinState(): Int = synchronized(lock) { joinState }

        @JvmStatic
        fun joinAddress(): String? = synchronized(lock) { joinAddress }

        @JvmStatic
        fun joinPrefix(): Int = synchronized(lock) { joinPrefix }

        @JvmStatic
        fun joinGateway(): String? = synchronized(lock) { joinGateway }

        // Joined with newlines, so the JNI side, which cannot safely build
        // the array's constructor, splits on lines; empty when nothing is
        // missing.
        @JvmStatic
        fun missingPermissions(): String {
            val context = context() ?: return ""
            val missing = mutableListOf<String>()
            if (Build.VERSION.SDK_INT >= 33 &&
                context.checkSelfPermission(Manifest.permission.NEARBY_WIFI_DEVICES) !=
                PackageManager.PERMISSION_GRANTED
            ) {
                missing += Manifest.permission.NEARBY_WIFI_DEVICES
            }
            if (context.checkSelfPermission(Manifest.permission.CHANGE_WIFI_MULTICAST_STATE) !=
                PackageManager.PERMISSION_GRANTED
            ) {
                missing += Manifest.permission.CHANGE_WIFI_MULTICAST_STATE
            }
            return missing.joinToString("\n")
        }

        @JvmStatic
        fun requestPermissions(activity: Activity) {
            // The prompt's activity stands the context's public route, so the
            // cache seeds from it for the JNI-threaded calls.
            cachedContext = activity.applicationContext
            val missing = missingPermissions().split("\n").filter { it.isNotEmpty() }.toMutableList()
            if (Build.VERSION.SDK_INT >= 31) {
                // The beacon and the exchange ask for theirs beside the
                // hotspot's own, so the one prompt covers the peer link,
                // while hosting and joining check only their own.
                for (name in listOf(
                    Manifest.permission.BLUETOOTH_SCAN,
                    Manifest.permission.BLUETOOTH_CONNECT,
                    Manifest.permission.BLUETOOTH_ADVERTISE
                )) {
                    if (activity.checkSelfPermission(name) != PackageManager.PERMISSION_GRANTED) {
                        missing += name
                    }
                }
            }
            if (missing.isNotEmpty()) {
                activity.requestPermissions(missing.toTypedArray(), PERMISSION_REQUEST)
            }
        }

        @JvmStatic
        fun bindSocket(fd: Int): Boolean {
            val network = synchronized(lock) { joinNetwork } ?: return false
            val pfd = runCatching { ParcelFileDescriptor.adoptFd(fd) }.getOrNull()
                ?: return false
            return try {
                // The network binds through the file descriptor, and the fd
                // is the socket's, not the descriptor's, so Java must never
                // close it out from under the dial.
                network.bindSocket(pfd.fileDescriptor)
                true
            } catch (e: Exception) {
                false
            } finally {
                runCatching { pfd.detachFd() }
            }
        }

        private fun context(): Context? {
            cachedContext?.let { return it }
            val context = contextFromFramework()
            if (context != null) cachedContext = context
            return context
        }

        private fun contextFromFramework(): Context? = runCatching {
            val application =
                Class.forName("android.app.ActivityThread")
                    .getMethod("currentApplication")
                    .invoke(null)
            application as? Context
        }.getOrNull()

        // The user's leave, or the join's request replacing it.
        private fun leaveLocked() {
            unregisterLocked()
            joinAddress = null
            joinPrefix = 0
            joinGateway = null
            joinState = JOIN_IDLE
        }

        // The network is gone or released, so the callback and the network
        // go with it. The state stands, the client steers it.
        private fun unregisterLocked() {
            val callback = joinCallback ?: return
            val context = context() ?: return
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE)
                as ConnectivityManager
            runCatching { cm.unregisterNetworkCallback(callback) }
            joinCallback = null
            joinNetwork = null
        }

        private fun fillInFrom(linkProperties: LinkProperties) {
            val address = linkProperties.linkAddresses
                .firstOrNull { it.address is Inet4Address }
            joinAddress = (address?.address as? Inet4Address)?.hostAddress
            joinPrefix = address?.prefixLength ?: 0
            val gateway = linkProperties.routes
                .firstOrNull { it.isDefaultRoute && it.hasGateway() }
                ?.gateway
                ?: linkProperties.routes
                    .firstOrNull { it.hasGateway() }
                    ?.gateway
            joinGateway = (gateway as? Inet4Address)?.hostAddress
            if (joinAddress != null && joinGateway != null) {
                joinState = JOIN_AVAILABLE
            }
        }
    }
}
