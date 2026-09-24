package dev.connetto.authsession

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import java.util.concurrent.atomic.AtomicReference

/**
 * Opens a login in a Custom Tab and hands back the redirect [RedirectActivity]
 * received.
 *
 * The tab is launched through the Custom Tabs protocol itself, an ACTION_VIEW
 * intent carrying the session extra, so the module needs no androidx.browser.
 * A browser without Custom Tabs support opens the URL as an ordinary page.
 */
class AuthSessionPlugin(private val activity: Activity) {
    fun begin(url: String) {
        pending.set(null)
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
        val extras = Bundle()
        extras.putBinder(EXTRA_SESSION, null)
        intent.putExtras(extras)
        activity.runOnUiThread { activity.startActivity(intent) }
    }

    fun takeRedirect(): String? = pending.getAndSet(null)

    companion object {
        private const val EXTRA_SESSION = "android.support.customtabs.extra.SESSION"
        private val pending = AtomicReference<String?>(null)

        internal fun deliver(uri: String?) {
            if (uri != null) {
                pending.set(uri)
            }
        }
    }
}
