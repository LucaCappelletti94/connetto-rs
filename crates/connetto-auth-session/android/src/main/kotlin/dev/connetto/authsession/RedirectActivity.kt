package dev.connetto.authsession

import android.app.Activity
import android.content.Intent
import android.os.Bundle

/**
 * Receives the login redirect, stores it for [AuthSessionPlugin], and returns
 * to the app's running activity, clearing the Custom Tab above it.
 */
class RedirectActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AuthSessionPlugin.deliver(intent?.dataString)
        packageManager.getLaunchIntentForPackage(packageName)?.let { launch ->
            // SINGLE_TOP keeps the running activity, so the app is not restarted.
            launch.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            startActivity(launch)
        }
        finish()
    }
}
