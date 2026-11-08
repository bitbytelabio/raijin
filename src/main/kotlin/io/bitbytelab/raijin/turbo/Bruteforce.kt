package io.bitbytelab.raijin.turbo

/** Generates lowercase bruteforce words (a..z, aa..zz, ...) for `wordlists.bruteforce`. */
class Bruteforce {
    companion object {
        private val DIGITS = charArrayOf(
            '0', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
            'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
        )

        @JvmStatic
        fun generate(seed: Int, count: Int, accumulator: MutableList<String>): Int {
            var num = seed
            var limit = seed + count
            while (num < limit) {
                val word = num2word(num)
                if (word != null) accumulator.add(word) else limit++
                num++
            }
            return num
        }

        private fun num2word(num: Int): String? {
            val number = num2String(num)
            return if (number.contains("0")) null else number
        }

        private fun num2String(input: Int): String {
            require(input >= 0) { "+ve integers only please" }
            val buf = CharArray(7)
            var charPos = 6
            var i = -input
            while (i <= -DIGITS.size) {
                buf[charPos--] = DIGITS[-(i % DIGITS.size)]
                i /= DIGITS.size
            }
            buf[charPos] = DIGITS[-i]
            return String(buf, charPos, 7 - charPos)
        }
    }
}
