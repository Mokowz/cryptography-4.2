import binascii
import re
import math
import string
import itertools
from collections import Counter
import numpy as np
from typing import List, Dict, Tuple, Optional, Any, Union

class CiphertextManager:
    """Manages loading and accessing ciphertexts."""

    def __init__(self, filename):
        self.ciphertexts = self.load_ciphertexts(filename)

    def load_ciphertexts(self, filename):
        """Loads hex-encoded ciphertexts from a file and converts them to bytes."""
        with open(filename, 'r') as f:
            hex_ciphertexts = [line.strip() for line in f if line.strip()]
        return [binascii.unhexlify(hex_ct) for hex_ct in hex_ciphertexts]

    def get_target(self):
        """Returns the 11th ciphertext (target)."""
        return self.ciphertexts[-1]

    def get_others(self):
        """Returns all ciphertexts except the target."""
        return self.ciphertexts[:-1]
class FrequencyAnalyzer:
    """Performs advanced frequency analysis on text data."""
    
    def __init__(self):
        # Single character frequencies for English language
        self.english_letter_freq = {
            'e': 12.02, 't': 9.10, 'a': 8.12, 'o': 7.68, 'i': 7.31, 'n': 6.95, 's': 6.28, 'r': 6.02, 
            'h': 5.92, 'd': 4.32, 'l': 3.98, 'u': 2.88, 'c': 2.71, 'm': 2.61, 'f': 2.30, 'y': 2.11, 
            'w': 2.09, 'g': 2.03, 'p': 1.82, 'b': 1.49, 'v': 1.11, 'k': 0.69, 'x': 0.17, 'q': 0.11, 
            'j': 0.10, 'z': 0.07, ' ': 13.00
        }
        
        # Common English digrams (frequency per 1000)
        self.english_digram_freq = {
            'th': 27.16, 'he': 23.48, 'in': 21.94, 'er': 17.96, 'an': 16.84, 're': 15.31, 
            'on': 15.31, 'at': 14.20, 'en': 13.64, 'nd': 13.63, 'ti': 13.62, 'es': 13.56, 
            'or': 12.95, 'te': 12.88, 'of': 12.59, 'ed': 12.39, 'is': 11.76, 'it': 11.69, 
            'al': 11.25, 'ar': 10.95, 'st': 10.85, 'to': 10.60, 'nt': 10.55, 'ng': 10.14, 
            'se': 9.58, 'ha': 9.55, 'as': 8.50, 'ou': 8.27, 'io': 7.82, 'le': 7.73, 
            've': 7.55, 'co': 7.51, 'me': 7.50, 'de': 7.30, 'hi': 6.96, 'ri': 6.84, 
            'ro': 6.54, 'ic': 6.34, 'ne': 6.18, 'ea': 6.03, 'ra': 5.99, 'ce': 5.90, 
            'li': 5.66, 'ch': 5.54, 'll': 5.45, 'be': 5.43, 'ma': 5.36, 'si': 5.33
        }
        
        # Common English trigrams (frequency per 1000)
        self.english_trigram_freq = {
            'the': 18.20, 'and': 7.51, 'ing': 7.10, 'her': 4.10, 'hat': 3.90, 
            'his': 3.68, 'tha': 3.45, 'ere': 3.20, 'for': 3.10, 'ent': 3.05, 
            'ion': 2.95, 'ter': 2.85, 'was': 2.80, 'you': 2.75, 'ith': 2.70, 
            'ver': 2.60, 'all': 2.50, 'wit': 2.45, 'thi': 2.40, 'tio': 2.35
        }
        
        # Index of Coincidence for English text
        self.english_ioc = 0.067
        
        # Common cryptographic patterns and phrases (useful as cribs)
        self.crypto_patterns = [
            "The magic words are squeamish ossifrage",
            "Cryptography is the practice and study of techniques",
            "The quick brown fox jumps over the lazy dog",
            "ETAOIN SHRDLU",
            "Attack at dawn",
            "Send reinforcements",
            "Secret message",
            "Top secret",
            "Confidential",
            "Encryption key",
            "Password is",
            "Your password is",
            "The password is",
            "Decrypt using",
            "private key",
            "public key",
            "RSA key",
            "security clearance",
            "authorization code",
            "authenticated",
            "verification",
            "authorization",
            "the answer is",
            "one time pad",
            "begins with",
            "ends with"
        ]
    
    def calculate_ioc(self, text: bytes) -> float:
        """Calculate the Index of Coincidence for a text."""
        try:
            # Convert to lowercase ASCII if possible
            text_str = text.decode('ascii', errors='replace').lower()
            
            # Count only alphabetic characters
            alphabet_only = ''.join(c for c in text_str if c.isalpha())
            
            if len(alphabet_only) <= 1:
                return 0.0
                
            # Count letter frequencies
            letter_counts = Counter(alphabet_only)
            
            # Calculate Index of Coincidence
            n = len(alphabet_only)
            sum_freqs = sum(count * (count - 1) for count in letter_counts.values())
            ioc = sum_freqs / (n * (n - 1)) if n > 1 else 0
            
            return ioc
        except:
            return 0.0
    
    def score_ngram_frequency(self, text: bytes, n: int = 1) -> float:
        """Score text based on n-gram frequency analysis."""
        try:
            text_str = text.decode('ascii', errors='replace').lower()
            
            if len(text_str) < n:
                return 0.0
                
            # Get reference frequencies based on n
            if n == 1:
                ref_freqs = self.english_letter_freq
            elif n == 2:
                ref_freqs = self.english_digram_freq
            elif n == 3:
                ref_freqs = self.english_trigram_freq
            else:
                return 0.0  # Only support 1, 2, 3-grams
            
            # Extract n-grams from text
            ngrams = [text_str[i:i+n] for i in range(len(text_str) - n + 1)]
            ngram_counts = Counter(ngrams)
            
            # Calculate score based on expected n-gram frequencies
            score = 0.0
            total_ngrams = len(ngrams)
            
            for ngram, count in ngram_counts.items():
                if ngram in ref_freqs:
                    expected = ref_freqs[ngram]
                    observed = (count / total_ngrams) * 100
                    # Reward for frequencies close to expected, penalize outliers
                    similarity = 1.0 - abs(observed - expected) / max(expected, 0.01)
                    score += similarity * count
            
            # Normalize score by text length
            normalized_score = score / max(1, len(text_str))
            return normalized_score
        except:
            return 0.0
    
    def comprehensive_text_score(self, text: bytes, weights: Dict[str, float] = None) -> float:
        """Calculate a comprehensive score based on multiple metrics."""
        if weights is None:
            weights = {
                'printable': 0.3,
                'unigram': 0.2,
                'digram': 0.2,
                'trigram': 0.15,
                'ioc': 0.15
            }
        
        try:
            # Score for printable ASCII characters
            printable_count = sum(1 for c in text if 32 <= c <= 126)
            printable_ratio = printable_count / max(1, len(text))
            printable_score = printable_ratio * 100
            
            # N-gram frequency scores
            unigram_score = self.score_ngram_frequency(text, 1)
            digram_score = self.score_ngram_frequency(text, 2)
            trigram_score = self.score_ngram_frequency(text, 3)
            
            # Index of Coincidence score
            ioc = self.calculate_ioc(text)
            ioc_ideal = self.english_ioc
            ioc_score = (1.0 - abs(ioc - ioc_ideal) / max(ioc_ideal, 0.01)) * 100
            
            # Combine scores with weights
            final_score = (
                weights['printable'] * printable_score +
                weights['unigram'] * unigram_score +
                weights['digram'] * digram_score +
                weights['trigram'] * trigram_score +
                weights['ioc'] * ioc_score
            )
            
            return final_score
        except:
            return 0.0
    
    def detect_language_statistics(self, text: bytes) -> Dict[str, float]:
        """Return detailed language statistics for a text."""
        stats = {}
        
        try:
            # Basic stats
            stats['length'] = len(text)
            stats['printable_ratio'] = sum(1 for c in text if 32 <= c <= 126) / max(1, len(text))
            stats['alpha_ratio'] = sum(1 for c in text if (65 <= c <= 90) or (97 <= c <= 122)) / max(1, len(text))
            stats['digit_ratio'] = sum(1 for c in text if 48 <= c <= 57) / max(1, len(text))
            stats['space_ratio'] = sum(1 for c in text if c == 32) / max(1, len(text))
            stats['punct_ratio'] = sum(1 for c in text if c in [33, 34, 39, 44, 45, 46, 58, 59, 63]) / max(1, len(text))
            
            # Frequency analysis
            stats['ioc'] = self.calculate_ioc(text)
            stats['unigram_score'] = self.score_ngram_frequency(text, 1)
            stats['digram_score'] = self.score_ngram_frequency(text, 2)
            stats['trigram_score'] = self.score_ngram_frequency(text, 3)
            
            # Entropy calculation (higher entropy = more random)
            text_str = text.decode('ascii', errors='replace')
            char_counts = Counter(text_str)
            probs = [count / len(text_str) for count in char_counts.values()]
            stats['entropy'] = -sum(p * math.log2(p) for p in probs)
            
            # Comprehensive score
            stats['comprehensive_score'] = self.comprehensive_text_score(text)
            
            return stats
        except:
            # Return basic stats if error occurs
            return {'comprehensive_score': 0.0, 'length': len(text)}


class KeyLengthDetector:
    """Detects potential key lengths using various methods."""
    
    def __init__(self, ciphertext):
        self.ciphertext = ciphertext
        self.analyzer = FrequencyAnalyzer()
    
    def hamming_distance(self, bytes1, bytes2) -> int:
        """Calculate Hamming distance between two byte sequences."""
        # Make sure the sequences are the same length
        min_len = min(len(bytes1), len(bytes2))
        bytes1 = bytes1[:min_len]
        bytes2 = bytes2[:min_len]
        
        # XOR the sequences and count the 1 bits
        xored = bytes(a ^ b for a, b in zip(bytes1, bytes2))
        return sum(bin(byte).count('1') for byte in xored)
    
    def normalized_hamming_distance(self, key_length: int) -> float:
        """Calculate normalized Hamming distance for blocks of given key length."""
        if key_length <= 0 or len(self.ciphertext) < key_length * 4:
            return float('inf')
        
        # Extract blocks
        blocks = [self.ciphertext[i:i+key_length] for i in range(0, len(self.ciphertext) - key_length * 2, key_length)]
        
        # Calculate average Hamming distance between consecutive blocks
        total_distance = 0
        comparisons = 0
        
        for i in range(len(blocks) - 1):
            distance = self.hamming_distance(blocks[i], blocks[i+1])
            total_distance += distance
            comparisons += 1
        
        if comparisons == 0:
            return float('inf')
            
        # Normalize by key length and number of comparisons
        return (total_distance / comparisons) / key_length
    
    def find_key_length(self, min_length: int = 2, max_length: int = 40) -> List[Tuple[int, float]]:
        """Find potential key lengths using Hamming distance."""
        distances = []
        
        for length in range(min_length, min(max_length+1, len(self.ciphertext)//4)):
            distance = self.normalized_hamming_distance(length)
            distances.append((length, distance))
        
        # Sort by normalized distance (ascending)
        sorted_distances = sorted(distances, key=lambda x: x[1])
        
        return sorted_distances
    
    def ioc_by_key_length(self, key_length: int) -> float:
        """Calculate average Index of Coincidence for columns with given key length."""
        if key_length <= 0 or len(self.ciphertext) < key_length * 2:
            return 0.0
        
        # Divide ciphertext into columns based on key length
        columns = [[] for _ in range(key_length)]
        for i, byte in enumerate(self.ciphertext):
            columns[i % key_length].append(byte)
        
        # Calculate IoC for each column
        iocs = []
        for column in columns:
            column_bytes = bytes(column)
            ioc = self.analyzer.calculate_ioc(column_bytes)
            iocs.append(ioc)
        
        # Return average IoC
        return sum(iocs) / len(iocs) if iocs else 0.0

class XORAnalyzer:
    """Handles XOR operations and plaintext recovery."""
    def __init__(self, ciphertexts):
        self.ciphertexts = ciphertexts
        self.target = ciphertexts[-1]
        self.others = ciphertexts[:-1]
        self.english_letter_freq = {
            'e': 12.02, 't': 9.10, 'a': 8.12, 'o': 7.68, 'i': 7.31, 'n': 6.95, 's': 6.28, 'r': 6.02, 
            'h': 5.92, 'd': 4.32, 'l': 3.98, 'u': 2.88, 'c': 2.71, 'm': 2.61, 'f': 2.30, 'y': 2.11, 
            'w': 2.09, 'g': 2.03, 'p': 1.82, 'b': 1.49, 'v': 1.11, 'k': 0.69, 'x': 0.17, 'q': 0.11, 
            'j': 0.10, 'z': 0.07, ' ': 13.00
        }
        self.common_cribs = [
            "The magic words are squeamish ossifrage",
            " the ", " and ", " is ", " to ", " of ", " in ", " for ", " that ", " have ", " with ",
            "The ", "A ", "In ", "Of ", "To ", "And ", "For ", "Is ", "It ", "At ", "On ", "This ",
            "the", "and", "for", "that", "have", "with", "not", "from", "this", "but", "what", "all"
        ]

    def xor_ciphertexts(self, c1, c2):
        """XORs two ciphertexts up to the length of the shorter one."""
        min_len = min(len(c1), len(c2))
        return bytes(a ^ b for a, b in zip(c1[:min_len], c2[:min_len]))

    def is_letter(self, byte):
        """Checks if a byte is an ASCII letter (A-Z or a-z)."""
        return 0x41 <= byte <= 0x5A or 0x61 <= byte <= 0x7A

    def analyze_space_positions(self):
        """Identifies positions in the target likely to be spaces."""
        target_len = len(self.target)
        space_positions = []
        for k in range(target_len):
            xor_results = [
                self.xor_ciphertexts(self.target, c)[k]
                for c in self.others if len(c) > k
            ]
            letter_count = sum(1 for x in xor_results if self.is_letter(x))
            if len(xor_results) > 0 and letter_count / len(xor_results) > 0.6:  # Lowered threshold from 0.7 to 0.6
                space_positions.append(k)
        return space_positions

    def recover_keystream_from_spaces(self, space_positions):
        """Recovers keystream bytes at positions assumed to be spaces."""
        keystream = [None] * len(self.target)
        for k in space_positions:
            keystream[k] = self.target[k] ^ 0x20  # XOR with space (0x20)
        return keystream

    def decrypt_with_keystream(self, ciphertext, keystream):
        """Decrypts a ciphertext using a partial keystream."""
        return bytes(c ^ k if k is not None else 0 for c, k in zip(ciphertext, keystream))
        
    def score_english_text(self, text):
        """Score the text based on character frequency similarity to English."""
        try:
            text_str = text.decode('ascii', errors='replace').lower()
            # Count characters
            char_count = Counter(text_str)
            total_chars = len(text_str)
            
            # Calculate score based on character frequency
            score = 0
            for char, freq in char_count.items():
                expected_freq = self.english_letter_freq.get(char, 0)
                observed_freq = (freq / total_chars) * 100
                score += min(observed_freq, expected_freq)
                
            # Penalize non-printable characters
            printable_ratio = sum(1 for c in text if 32 <= c <= 126) / len(text) if len(text) > 0 else 0
            score *= printable_ratio
                
            return score
        except:
            return 0
            
    def is_likely_english(self, text, min_score=30):
        """Check if a text is likely to be English."""
        try:
            text_str = text.decode('ascii', errors='replace')
            
            # Check if text contains reasonable word patterns
            word_pattern = re.compile(r'[a-zA-Z]{2,}')
            words = word_pattern.findall(text_str)
            
            # Check for reasonable word/space distribution
            if len(words) < 3 and len(text_str) > 15:
                return False
                
            # Check the frequency score
            score = self.score_english_text(text)
            return score >= min_score
        except:
            return False
            
    def combine_crib_results(self, crib_results):
        """Combine keystream fragments from multiple cribs."""
        target_len = len(self.target)
        combined_keystream = [None] * target_len
        
        # Sort results by score (highest first)
        sorted_results = sorted(crib_results, key=lambda x: x['score'], reverse=True)
        
        # Apply each keystream fragment based on score order
        for result in sorted_results:
            keystream = result['keystream']
            start_pos = result['position']
            crib_len = result['crib_length']
            
            # Only apply if position is not yet filled or if score is higher
            for i in range(start_pos, min(start_pos + crib_len, target_len)):
                combined_keystream[i] = keystream[i - start_pos]
                
        return combined_keystream

    def crib_drag(self, crib, return_results=False):
        """Slides a crib across the target to find the secret message."""
        crib_bytes = crib.encode('ascii')
        crib_len = len(crib_bytes)
        target_len = len(self.target)
        print(f"\nCrib dragging with: '{crib}'")
        
        results = []
        
        for s in range(target_len - crib_len + 1):
            keystream_segment = self.xor_ciphertexts(
                self.target[s:s + crib_len], crib_bytes)
            # Test the keystream segment on other ciphertexts
            for c in self.others:
                if len(c) >= s + crib_len:
                    decrypted = self.xor_ciphertexts(
                        c[s:s + crib_len], keystream_segment)
                    if all(32 <= b <= 126 for b in decrypted):  # Printable ASCII
                        # Decrypt the target with this keystream segment
                        keystream = [None] * target_len
                        keystream[s:s + crib_len] = keystream_segment
                        decrypted_target = self.decrypt_with_keystream(
                            self.target, keystream)
                        
                        # Score the result
                        score = self.score_english_text(decrypted)
                        
                        # Only show promising results
                        if self.is_likely_english(decrypted) or score > 40:
                            print(f"Position {s}: Decrypted snippet from another ciphertext: {decrypted.decode('ascii')}")
                            print(f"Score: {score:.2f}")
                            print(f"Decrypted target: {decrypted_target.decode('ascii', errors='replace')}")
                        
                        if return_results:
                            results.append({
                                'position': s,
                                'keystream': keystream_segment,
                                'crib_length': crib_len,
                                'score': score,
                                'decrypted_sample': decrypted,
                                'decrypted_target': decrypted_target
                            })
        
        if return_results:
            return results
    def multi_crib_analysis(self):
        """Runs analysis with multiple cribs and combines results."""
        all_results = []
        
        for crib in self.common_cribs:
            results = self.crib_drag(crib, return_results=True)
            if results:
                all_results.extend(results)
                
        # Filter to keep only promising results
        promising_results = [r for r in all_results if r['score'] > 30]
        
        if promising_results:
            # Combine the keystream fragments from promising results
            combined_keystream = self.combine_crib_results(promising_results)
            
            # Decrypt with combined keystream
            decrypted_target = self.decrypt_with_keystream(self.target, combined_keystream)
            score = self.score_english_text(decrypted_target)
            
            print("\n--- Combined Results from Multiple Cribs ---")
            print(f"Combined Score: {score:.2f}")
            print(f"Decrypted target: {decrypted_target.decode('ascii', errors='replace')}")
            
            return decrypted_target, score
        return None, 0


def main():
    # Initialize with the ciphertext file
    manager = CiphertextManager('ciphertexts.txt')
    analyzer = XORAnalyzer(manager.ciphertexts)
    
    # Method 1: Space-position analysis
    print("\nAnalyzing space positions...")
    space_positions = analyzer.analyze_space_positions()
    space_keystream = analyzer.recover_keystream_from_spaces(space_positions)
    space_decrypted = analyzer.decrypt_with_keystream(analyzer.target, space_keystream)
    space_score = analyzer.score_english_text(space_decrypted)
    print(f"Space analysis score: {space_score:.2f}")
    print(f"Decrypted target with space analysis: {space_decrypted.decode('ascii', errors='replace')}")
    
    # Method 2: Try the expected secret message first
    main_crib = "The magic words are squeamish ossifrage"
    print(f"\nCrib dragging with main hypothesis: '{main_crib}'")
    analyzer.crib_drag(main_crib)
    
    # Method 3: Analysis with multiple cribs and combining results
    print("\nPerforming multi-crib analysis with common English patterns...")
    multi_crib_decrypted, multi_crib_score = analyzer.multi_crib_analysis()
    
    # Final output - compare and select best result
    print("\n--- Final Results ---")
    results = [
        ("Space Analysis", space_decrypted, space_score),
        ("Multi-Crib Analysis", multi_crib_decrypted, multi_crib_score if multi_crib_decrypted else 0)
    ]
    
    best_result = max(results, key=lambda x: x[2])
    print(f"Best decryption method: {best_result[0]} (Score: {best_result[2]:.2f})")
    print(f"Final decrypted message: {best_result[1].decode('ascii', errors='replace')}")


if __name__ == "__main__":
    main()