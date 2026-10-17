package dev.connetto.authsession

import android.app.Activity
import android.app.Application
import android.os.Bundle
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The app screen in front, which the sign-in tab and the unlock prompt open
 * on. Android rebuilds a screen inside the running process, as it does when the
 * text size changes, so the plugins look the screen up each time they act
 * instead of keeping one.
 *
 * The lifecycle callbacks run on the main thread, which is also the only thread
 * that adds or ends a destroy wait. A relaunch destroys and creates in one
 * main-thread message, so main-thread code sees the old screen or the new one.
 */
object CurrentActivity : Application.ActivityLifecycleCallbacks {
    @Volatile
    private var current: Activity? = null

    @Volatile
    private var application: Application? = null

    private val installed = AtomicBoolean(false)
    private val destroyWaits = mutableListOf<Pair<Activity, () -> Unit>>()

    internal fun install(app: Application) {
        if (installed.compareAndSet(false, true)) {
            application = app
            app.registerActivityLifecycleCallbacks(this)
        }
    }

    /** The screen in front, or `null` when the app shows none. */
    fun get(): Activity? = current

    /** The Application, which [CurrentActivityProvider] installs at process start. */
    fun application(): Application =
        application ?: throw IllegalStateException(
            "dev.connetto.authsession.CurrentActivityProvider is not declared in the app's manifest",
        )

    /**
     * Run [action] on the main thread once [activity] is destroyed, unless the
     * returned function cancels it first. Main thread only.
     */
    internal fun onDestroyed(activity: Activity, action: () -> Unit): () -> Unit {
        val wait = activity to action
        destroyWaits.add(wait)
        return { destroyWaits.remove(wait) }
    }

    override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) = track(activity)

    override fun onActivityResumed(activity: Activity) = track(activity)

    override fun onActivityDestroyed(activity: Activity) {
        if (current === activity) {
            current = null
        }
        val ended = destroyWaits.filter { it.first === activity }
        destroyWaits.removeAll(ended)
        ended.forEach { it.second() }
    }

    override fun onActivityStarted(activity: Activity) = Unit

    override fun onActivityPaused(activity: Activity) = Unit

    override fun onActivityStopped(activity: Activity) = Unit

    override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit

    // The redirect screen only hands the redirect on and finishes at once.
    private fun track(activity: Activity) {
        if (activity !is RedirectActivity) {
            current = activity
        }
    }
}
