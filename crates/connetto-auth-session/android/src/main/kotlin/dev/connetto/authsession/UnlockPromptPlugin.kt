package dev.connetto.authsession

import android.annotation.TargetApi
import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.view.ViewTreeObserver
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Cipher

/**
 * Approves the cipher a Keystore-gated store unlocks with, through the
 * platform's biometric or device-credential prompt, and reports whether the
 * device has the secure lock screen such a key needs.
 *
 * The prompt is the framework's own, so the module needs no androidx.biometric
 * and the screen in front need not be a FragmentActivity. The cipher rides the
 * prompt as its CryptoObject, which is what authorizes the key for the one
 * operation the store runs with it. A strong biometric or the device
 * credential is accepted, never a biometric alone, since re-registering a
 * finger destroys a key that accepts only that.
 */
class UnlockPromptPlugin {
    fun deviceSecure(): Boolean =
        (CurrentActivity.application().getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager)
            .isDeviceSecure

    fun begin(cipher: Cipher, title: String) {
        CurrentActivity.requireInstalled()
        outcome.set(PENDING)
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            outcome.set(UNAVAILABLE)
            return
        }
        Handler(Looper.getMainLooper()).post {
            val activity = CurrentActivity.get()
            if (activity == null) {
                outcome.set(NO_SCREEN)
            } else {
                whenFocused(activity) { show(activity, cipher, title) }
            }
        }
    }

    /**
     * Runs [action] once [activity]'s window holds focus. A prompt asked while
     * another app is in front, as the login tab is for a moment after the
     * redirect, is taken for a background request and never shown on Samsung.
     * A screen destroyed before it gains focus never will, so the wait ends as
     * dismissed and the app may ask again on the screen that replaced it.
     */
    private fun whenFocused(activity: Activity, action: () -> Unit) {
        val decor = activity.window.decorView
        if (decor.hasWindowFocus()) {
            action()
            return
        }
        val listener = object : ViewTreeObserver.OnWindowFocusChangeListener {
            lateinit var cancelDestroyWait: () -> Unit

            override fun onWindowFocusChanged(hasFocus: Boolean) {
                if (hasFocus) {
                    decor.viewTreeObserver.removeOnWindowFocusChangeListener(this)
                    cancelDestroyWait()
                    action()
                }
            }
        }
        listener.cancelDestroyWait = CurrentActivity.onDestroyed(activity) {
            decor.viewTreeObserver.removeOnWindowFocusChangeListener(listener)
            outcome.set(DISMISSED)
        }
        decor.viewTreeObserver.addOnWindowFocusChangeListener(listener)
    }

    fun takeOutcome(): Int = outcome.get()

    @TargetApi(Build.VERSION_CODES.R)
    private fun show(activity: Activity, cipher: Cipher, title: String) {
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
        const val NO_SCREEN = 5
        private val outcome = AtomicInteger(PENDING)
    }
}
