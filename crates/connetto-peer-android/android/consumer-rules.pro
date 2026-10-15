# btleplug's Java and its vendored jni-utils are reached only through JNI,
# so R8 would strip them as unused.
-keep class com.nonpolynomial.** { *; }
-keep class io.github.gedgygedgy.** { *; }
