package dev.connetto.peer

import android.Manifest
import android.app.Activity
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import java.util.Base64
import java.util.UUID

/**
 * The Bluetooth beacon and the GATT service the exchange runs over (R76).
 *
 * All state stands behind [lock]; the [JvmStatic]s are the JNI surface the
 * client drives. The readiness stands on the adapter's switch and the
 * three runtime permissions. The host side starts a legacy advertisement
 * carrying the beacon's service data under the service uuid, and a GATT
 * server with the characteristic the joiner writes and the one it reads
 * notifications from. The client polls [poll] for the events, whose lines
 * are tab-separated and carry their bytes base64-encoded.
 */
class BluetoothPlugin {
    companion object {
        // The service the GATT server stands under, and the characteristics
        // the joiner writes to and reads notifications from (R76 decision 18).
        private val SERVICE_UUID = UUID.fromString("a9952637-85d5-4071-9ed8-c28bd7ba670c")
        private val INBOX_UUID = UUID.fromString("bdd3f20f-a8d0-4003-82db-4f941b4c375b")
        private val OUTBOX_UUID = UUID.fromString("62ba3a58-c377-47f5-93e1-cd6790bc2e53")

        // The client characteristic configuration the joiner writes to
        // turn its notifications on.
        private val CCC_UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

        // The main thread, where the prompt's dialogs open.
        private val handler = Handler(Looper.getMainLooper())

        // The ATT packet size a connection has before any exchange.
        private const val DEFAULT_MTU = 23

        // The readiness, as the client reads it.
        private const val STATE_UNSUPPORTED = 0
        private const val STATE_READY = 1
        private const val STATE_OFF = 2
        private const val STATE_NOT_PERMITTED = 3

        // The finished prompt action's result, and the in-flight marker.
        private const val OUTCOME_NOT_ASKED = 0
        private const val OUTCOME_DECLINED = 1
        private const val OUTCOME_SENT_TO_SETTINGS = 2
        private const val OUTCOME_BLOCKED = 3
        private const val OUTCOME_IN_FLIGHT = -1

        // The prompt action's start.
        private const val PROMPT_STARTED = 0
        private const val PROMPT_BLOCKED = 1

        private const val OK = 0
        private const val FAILED = 1

        // The keys the prompt's dialogs register their answers under.
        private const val PERMISSIONS_KEY = "dev.connetto.peer.bluetooth-permissions"
        private const val ENABLE_KEY = "dev.connetto.peer.bluetooth-enable"

        // The event lines' codes.
        private const val EVENT_CONNECTED = 1
        private const val EVENT_DISCONNECTED = 2
        private const val EVENT_FAILED = 3
        private const val EVENT_CHUNK = 4

        private val lock = Any()

        private var cachedContext: Context? = null
        private var promptOutcome = OUTCOME_IN_FLIGHT

        private var advertising = false
        private var gattServer: BluetoothGattServer? = null
        private var outbox: BluetoothGattCharacteristic? = null
        private val devices = HashMap<Long, BluetoothDevice>()
        private val mtus = HashMap<Long, Int>()
        private val connected = HashMap<Long, Boolean>()
        private val eventLines = ArrayDeque<String>()
        private val notifying = HashMap<Long, Boolean>()
        private val notifyQueue = HashMap<Long, ArrayDeque<ByteArray>>()
        private val ccc = HashMap<Long, ByteArray>()

        @JvmStatic
        fun state(): Int = synchronized(lock) {
            val adapter = adapter() ?: return STATE_UNSUPPORTED
            if (!adapter.isEnabled) return STATE_OFF
            if (missingPermissionsLocked().isNotEmpty()) return STATE_NOT_PERMITTED
            STATE_READY
        }

        // Joined with newlines, so the JNI side, which cannot safely build
        // the array's constructor, splits on lines.
        @JvmStatic
        fun missingPermissions(): String =
            synchronized(lock) { missingPermissionsLocked().joinToString("\n") }

        @JvmStatic
        fun prompt(activity: Activity): Int = synchronized(lock) {
            promptOutcome = OUTCOME_IN_FLIGHT
            val adapter = adapter() ?: return PROMPT_BLOCKED
            val missing = missingPermissionsLocked()
            if (missing.isEmpty() && adapter.isEnabled) {
                promptOutcome = OUTCOME_NOT_ASKED
                return PROMPT_STARTED
            }
            // The dialogs answer through the Activity's result registry,
            // which the application's AppCompat Activity carries.
            val component = activity as? ComponentActivity ?: run {
                promptOutcome = OUTCOME_BLOCKED
                return PROMPT_BLOCKED
            }
            // The dialogs open from the main thread, which the caller may
            // not be on.
            handler.post {
                try {
                    if (missing.isNotEmpty()) {
                        askPermissions(component, missing)
                    } else {
                        askEnable(component)
                    }
                } catch (e: Exception) {
                    synchronized(lock) { promptOutcome = OUTCOME_BLOCKED }
                }
            }
            PROMPT_STARTED
        }

        private fun askPermissions(activity: ComponentActivity, missing: List<String>) {
            var launcher: ActivityResultLauncher<Array<String>>? = null
            launcher = activity.activityResultRegistry.register(
                PERMISSIONS_KEY,
                ActivityResultContracts.RequestMultiplePermissions()
            ) { granted ->
                launcher?.unregister()
                synchronized(lock) {
                    promptOutcome =
                        if (granted.values.all { it }) OUTCOME_NOT_ASKED else OUTCOME_DECLINED
                }
            }
            launcher.launch(missing.toTypedArray())
        }

        private fun askEnable(activity: ComponentActivity) {
            var launcher: ActivityResultLauncher<Intent>? = null
            launcher = activity.activityResultRegistry.register(
                ENABLE_KEY,
                ActivityResultContracts.StartActivityForResult()
            ) { result ->
                launcher?.unregister()
                synchronized(lock) {
                    promptOutcome =
                        if (result.resultCode == Activity.RESULT_OK) OUTCOME_NOT_ASKED
                        else OUTCOME_DECLINED
                }
            }
            launcher.launch(Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE))
        }

        @JvmStatic
        fun promptOutcome(): Int = synchronized(lock) { promptOutcome }

        @JvmStatic
        fun startAdvertising(beacon: ByteArray): Int = synchronized(lock) {
            stopLocked()
            val manager = manager() ?: return FAILED
            val service = BluetoothGattService(
                SERVICE_UUID,
                BluetoothGattService.SERVICE_TYPE_PRIMARY
            )
            val inbox = BluetoothGattCharacteristic(
                INBOX_UUID,
                BluetoothGattCharacteristic.PROPERTY_WRITE,
                BluetoothGattCharacteristic.PERMISSION_WRITE
            )
            service.addCharacteristic(inbox)
            val out = BluetoothGattCharacteristic(
                OUTBOX_UUID,
                BluetoothGattCharacteristic.PROPERTY_NOTIFY,
                BluetoothGattCharacteristic.PERMISSION_READ
            )
            out.addDescriptor(cccDescriptor())
            service.addCharacteristic(out)
            val server = manager.openGattServer(context(), gattCallback) ?: return FAILED
            if (!server.addService(service)) {
                server.close()
                return FAILED
            }
            gattServer = server
            outbox = out
            val advertiser = manager.adapter?.bluetoothLeAdvertiser ?: return FAILED
            val settings = AdvertiseSettings.Builder()
                .setConnectable(true)
                .build()
            val data = AdvertiseData.Builder()
                .setIncludeDeviceName(false)
                .addServiceData(ParcelUuid(SERVICE_UUID), beacon)
                .build()
            advertising = false
            advertiser.startAdvertising(settings, data, advertiseCallback)
            OK
        }

        @JvmStatic
        fun stopAdvertising() {
            synchronized(lock) { stopLocked() }
        }

        @JvmStatic
        fun poll(): String = synchronized(lock) {
            val lines = eventLines.joinToString("\n")
            eventLines.clear()
            lines
        }

        @JvmStatic
        fun notify(device: Long, bytes: ByteArray): Int = synchronized(lock) {
            val server = gattServer ?: return FAILED
            val target = devices[device] ?: return FAILED
            val characteristic = outbox ?: return FAILED
            val queue = notifyQueue.getOrPut(device) { ArrayDeque() }
            if (notifying.getOrDefault(device, false)) {
                // The platform allows one notification in flight per device,
                // so the next goes when the platform's sent callback fires.
                queue.addLast(bytes)
                return OK
            }
            val status = server.notifyCharacteristicChanged(
                target,
                characteristic,
                false,
                bytes
            )
            if (status != BluetoothGatt.GATT_SUCCESS) {
                dropLocked(device)
                return FAILED
            }
            notifying[device] = true
            OK
        }

        // A lost notification leaves a gap in the ordered byte stream the
        // exchange reads, so the connection ends at once and is reported.
        private fun dropLocked(key: Long) {
            val target = devices.remove(key) ?: return
            connected.remove(key)
            mtus.remove(key)
            notifying.remove(key)
            notifyQueue.remove(key)
            ccc.remove(key)
            eventLines.addLast("$EVENT_DISCONNECTED\t$key")
            runCatching { gattServer?.cancelConnection(target) }
        }

        @JvmStatic
        fun disconnectPeripheral(device: Long) {
            synchronized(lock) {
                val target = devices[device] ?: return
                runCatching { gattServer?.cancelConnection(target) }
            }
        }

        private fun missingPermissionsLocked(): List<String> {
            val context = context() ?: return emptyList()
            if (Build.VERSION.SDK_INT < 31) return emptyList()
            val names = listOf(
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.BLUETOOTH_ADVERTISE
            )
            return names
                .filter {
                    context.checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED
                }
                .map { it.substringAfterLast('.') }
        }

        private val advertiseCallback = object : AdvertiseCallback() {
            override fun onStartSuccess(settings: AdvertiseSettings) {
                synchronized(lock) { advertising = true }
            }

            override fun onStartFailure(status: Int) {
                synchronized(lock) {
                    advertising = false
                    eventLines.addLast("$EVENT_FAILED\t$status")
                }
            }
        }

        private val gattCallback = object : BluetoothGattServerCallback() {
            override fun onConnectionStateChange(
                device: BluetoothDevice?,
                status: Int,
                newState: Int
            ) {
                if (device == null) return
                val key = deviceKey(device)
                synchronized(lock) {
                    if (newState == BluetoothProfile.STATE_CONNECTED) {
                        devices[key] = device
                        connected[key] = true
                        // The client starts the exchange on the negotiated
                        // packet size, so the line waits for onMtuChanged.
                    } else {
                        // A connection a failed notification ended is
                        // already reported.
                        if (devices.remove(key) == null) return
                        connected.remove(key)
                        mtus.remove(key)
                        notifying.remove(key)
                        notifyQueue.remove(key)
                        ccc.remove(key)
                        eventLines.addLast("$EVENT_DISCONNECTED\t$key")
                    }
                }
            }

            override fun onMtuChanged(device: BluetoothDevice?, mtu: Int) {
                if (device == null) return
                val key = deviceKey(device)
                synchronized(lock) {
                    val first = !mtus.containsKey(key)
                    mtus[key] = mtu
                    if (first && connected[key] == true) {
                        eventLines.addLast("$EVENT_CONNECTED\t$key\t$mtu")
                    }
                }
            }

            override fun onCharacteristicWriteRequest(
                device: BluetoothDevice?,
                requestId: Int,
                characteristic: BluetoothGattCharacteristic,
                preparedWrite: Boolean,
                responseNeeded: Boolean,
                offset: Int,
                value: ByteArray?
            ) {
                if (device == null || value == null) return
                if (characteristic.uuid != INBOX_UUID) return
                val key = deviceKey(device)
                synchronized(lock) {
                    // A client that never exchanged a packet size writes on
                    // the default one, so the connection is reported first.
                    if (!mtus.containsKey(key) && connected[key] == true) {
                        mtus[key] = DEFAULT_MTU
                        eventLines.addLast("$EVENT_CONNECTED\t$key\t$DEFAULT_MTU")
                    }
                    eventLines.addLast(
                        "$EVENT_CHUNK\t$key\t" +
                            Base64.getEncoder().encodeToString(value)
                    )
                }
                if (responseNeeded) {
                    gattServer?.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt.GATT_SUCCESS,
                        offset,
                        null
                    )
                }
            }

            override fun onCharacteristicReadRequest(
                device: BluetoothDevice?,
                requestId: Int,
                offset: Int,
                characteristic: BluetoothGattCharacteristic
            ) {
                if (device == null) return
                // The joiner streams over the notifications, so the read
                // answers with the empty value.
                gattServer?.sendResponse(
                    device,
                    requestId,
                    BluetoothGatt.GATT_SUCCESS,
                    offset,
                    null
                )
            }

            override fun onDescriptorReadRequest(
                device: BluetoothDevice?,
                requestId: Int,
                offset: Int,
                descriptor: BluetoothGattDescriptor
            ) {
                if (device == null) return
                if (descriptor.uuid != CCC_UUID) return
                val key = deviceKey(device)
                val state = synchronized(lock) {
                    ccc[key] ?: BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE
                }
                gattServer?.sendResponse(
                    device,
                    requestId,
                    BluetoothGatt.GATT_SUCCESS,
                    offset,
                    state
                )
            }

            override fun onDescriptorWriteRequest(
                device: BluetoothDevice?,
                requestId: Int,
                descriptor: BluetoothGattDescriptor,
                preparedWrite: Boolean,
                responseNeeded: Boolean,
                offset: Int,
                value: ByteArray?
            ) {
                if (device == null || value == null) return
                if (descriptor.uuid != CCC_UUID) return
                val key = deviceKey(device)
                // The write turns the device's notifications on or off,
                // and the read-back stands on the stored value.
                synchronized(lock) { ccc[key] = value }
                if (responseNeeded) {
                    gattServer?.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt.GATT_SUCCESS,
                        offset,
                        null
                    )
                }
            }

            override fun onNotificationSent(device: BluetoothDevice?, status: Int) {
                if (device == null) return
                val key = deviceKey(device)
                synchronized(lock) {
                    if (status != BluetoothGatt.GATT_SUCCESS) {
                        dropLocked(key)
                        return
                    }
                    notifying[key] = false
                    val next = notifyQueue[key]?.removeFirstOrNull() ?: return
                    val server = gattServer ?: return
                    val characteristic = outbox ?: return
                    if (server.notifyCharacteristicChanged(
                            device,
                            characteristic,
                            false,
                            next
                        ) == BluetoothGatt.GATT_SUCCESS
                    ) {
                        notifying[key] = true
                    } else {
                        dropLocked(key)
                    }
                }
            }
        }

        private fun stopLocked() {
            runCatching {
                val manager = manager()
                manager?.adapter?.bluetoothLeAdvertiser?.stopAdvertising(advertiseCallback)
            }
            advertising = false
            gattServer?.close()
            gattServer = null
            outbox = null
            devices.clear()
            connected.clear()
            mtus.clear()
            notifying.clear()
            notifyQueue.clear()
            ccc.clear()
        }

        private fun cccDescriptor(): BluetoothGattDescriptor = BluetoothGattDescriptor(
            CCC_UUID,
            BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE
        )

        private fun deviceKey(device: BluetoothDevice): Long {
            val mac = device.address
            var key = 0L
            for (i in 0 until 6) {
                key = (key shl 8) or mac.substring(i * 3, i * 3 + 2).toLong(16)
            }
            return key
        }

        private fun manager(): BluetoothManager? =
            context()?.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager

        private fun adapter(): BluetoothAdapter? = manager()?.adapter

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
    }
}
