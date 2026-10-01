package dev.connetto.authsession

import android.annotation.TargetApi
import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.view.ViewTreeObserver
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Cipher

/**
 * Approves the cipher a Keystore-gated store unlocks with, through the
 * platform's biometric or device-credential prompt, and reports whether the
 * device has the secure lock screen such a key needs.
 *
 * The prompt is the framework's own, so the module needs no androidx.biometric
 * and the host Activity need not be a FragmentActivity. The cipher rides the
 * prompt as its CryptoObject, which is what authorizes the key for the one
 * operation the store runs with it. A strong biometric or the device
 * credential is accepted, never a biometric alone, since re-registering a
 * finger destroys a key that accepts only that.
 */
class UnlockPromptPlugin(private val activity: Activity) {
    fun deviceSecure(): Boolean =
        (activity.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isDeviceSecure

    fun begin(cipher: Cipher, title: String) {
        outcome.set(PENDING)
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            outcome.set(UNAVAILABLE)
            return
        }
        activity.runOnUiThread { whenFocused { show(cipher, title) } }
    }

    /**
     * Runs [action] once the app's window holds focus. A prompt asked while
     * another app is in front, as the login tab is for a moment after the
     * redirect, is taken for a background request and never shown on Samsung.
     */
    private fun whenFocused(action: () -> Unit) {
        val decor = activity.window.decorView
        if (decor.hasWindowFocus()) {
            action()
            return
        }
        val observer = decor.viewTreeObserver
        observer.addOnWindowFocusChangeListener(object : ViewTreeObserver.OnWindowFocusChangeListener {
            override fun onWindowFocusChanged(hasFocus: Boolean) {
                if (hasFocus) {
                    decor.viewTreeObserver.removeOnWindowFocusChangeListener(this)
                    action()
                }
            }
        })
    }

    fun takeOutcome(): Int = outcome.get()

    @TargetApi(Build.VERSION_CODES.R)
    private fun show(cipher: Cipher, title: String) {
        val prompt = BiometricPrompt.Builder(activity)
            .setTitle(title)
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                    BiometricManager.Authenticators.DEVICE_CREDENTIAL,
            )
            .build()
        prompt.authenticate(
            BiometricPrompt.CryptoObject(cipher),
            CancellationSignal(),
            activity.mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    outcome.set(APPROVED)
                }

                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    outcome.set(if (code == BiometricPrompt.BIOMETRIC_ERROR_CANCELED) CANCELED else DISMISSED)
                }
            },
        )
    }

    companion object {
        const val PENDING = 0
        const val APPROVED = 1
        const val DISMISSED = 2
        const val CANCELED = 3
        const val UNAVAILABLE = 4
        private val outcome = AtomicInteger(PENDING)
    }
}
