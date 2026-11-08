package io.bitbytelab.raijin.turbo

/** A script file on disk shown in the script picker. */
class DirectoryItem(val fullPath: String, val name: String) {
    override fun toString(): String = name
}
