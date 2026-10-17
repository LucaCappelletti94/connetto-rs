package dev.connetto.authsession

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Opens a login in a Custom Tab, from the screen in front, and hands back the
 * redirect [RedirectActivity] received.
 *
 * The tab is launched through the Custom Tabs protocol itself, an ACTION_VIEW
 * intent carrying the session extra, so the module needs no androidx.browser.
 * A browser without Custom Tabs support opens the URL as an ordinary page.
 */
class AuthSessionPlugin {
    fun begin(url: String) {
        pending.set(null)
        tab.set(TAB_PENDING)
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
        val extras = Bundle()
        extras.putBinder(EXTRA_SESSION, null)
        intent.putExtras(extras)
        Handler(Looper.getMainLooper()).post {
            val activity = CurrentActivity.get()
            if (activity == null) {
                tab.set(TAB_NO_SCREEN)
            } else {
                activity.startActivity(intent)
                tab.set(TAB_OPENED)
            }
        }
    }

    fun takeRedirect(): String? = pending.getAndSet(null)

    /** Whether the last [begin] opened its tab, one of the `TAB_` constants. */
    fun tabState(): Int = tab.get()

    companion object {
        const val TAB_PENDING = 0
        const val TAB_OPENED = 1
        const val TAB_NO_SCREEN = 2
        private const val EXTRA_SESSION = "android.support.customtabs.extra.SESSION"
        private val pending = AtomicReference<String?>(null)
        private val tab = AtomicInteger(TAB_PENDING)

        internal fun deliver(uri: String?) {
            if (uri != null) {
                pending.set(uri)
            }
        }
    }
}
