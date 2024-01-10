import jieba
from pinyin import pinyin, Style
import sys

def translate_to_pinyin(text):
    # Tokenize the input Chinese text using jieba
    words = jieba.cut(text)
    
    # Join the Pinyin of each word and add tone marks
    pinyin_words = [pinyin(word, style=Style.TONE3)[0][0] for word in words]
    
    # Return the Pinyin translation as a string
    return ' '.join(pinyin_words)

if __name__ == "__main__":
    return translate_to_pinyin(sys.argv[1])