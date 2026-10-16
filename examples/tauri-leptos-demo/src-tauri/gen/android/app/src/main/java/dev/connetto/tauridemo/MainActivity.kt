package dev.connetto.tauridemo

import android.app.Activity
import android.os.Bundle
import androidx.activity.enableEdgeToEdge

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
    // connetto-auth-session builds its sign-in and unlock plugins on the
    // activity, which the Rust core takes from ndk-context.
    publishActivity(this)
  }

  private external fun publishActivity(activity: Activity)
}
