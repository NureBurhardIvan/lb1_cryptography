using System.Text.RegularExpressions;
using System.Text;
using lb1_cryptography.Models;

namespace lb1_cryptography
{
    public class DesProcessor
    {
        #region constants
        private const int BlockSizeInBytes = 8;
        private const int NumRounds = 16;
        private const int KeySize = 56; // Number of bits in the key after permutation
        private const int HalfKeySize = 28; // Half the size of the key in bits
        private const int BlockSize = 64; // Size of the data block in bits
        private const int RoundKeySize = 48; // Size of the round key in bits
        private const int PermutedBlockSize = 32; // Size of the block after S-Box substitution
        private const int EntropyBits = 32; // Number of bits to calculate entropy
        private readonly int[] InitialPermutation =
            {
                58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7
            };
        private readonly int[] FinalPermutation =
            {
                40, 8, 48, 16, 56, 24, 64, 32,
                39, 7, 47, 15, 55, 23, 63, 31,
                38, 6, 46, 14, 54, 22, 62, 30,
                37, 5, 45, 13, 53, 21, 61, 29,
                36, 4, 44, 12, 52, 20, 60, 28,
                35, 3, 43, 11, 51, 19, 59, 27,
                34, 2, 42, 10, 50, 18, 58, 26,
                33, 1, 41, 9, 49, 17, 57, 25
            };
        private readonly int[] ExpansionTable =
            {
                 32, 1, 2, 3, 4, 5,
                 4, 5, 6, 7, 8, 9,
                 8, 9, 10, 11, 12, 13,
                 12, 13, 14, 15, 16, 17,
                 16, 17, 18, 19, 20, 21,
                 20, 21, 22, 23, 24, 25,
                 24, 25, 26, 27, 28, 29,
                 28, 29, 30, 31, 32, 1
            }; /* expansion table for right 32 bits to 48 bits*/
        private readonly int[] PBoxPermutation =
            {
                 16, 7, 20, 21,
                 29, 12, 28, 17,
                 1, 15, 23, 26,
                 5, 18, 31, 10,
                 2, 8, 24, 14,
                 32, 27, 3, 9,
                 19, 13, 30, 6,
                 22, 11, 4, 25
            };
        private readonly int[] PC1 =
        {
             57, 49, 41, 33, 25, 17, 9,
             1, 58, 50, 42, 34, 26, 18,
             10, 2, 59, 51, 43, 35, 27,
             19, 11, 3, 60, 52, 44, 36,
             63, 55, 47, 39, 31, 23, 15,
             7, 62, 54, 46, 38, 30, 22,
             14, 6, 61, 53, 45, 37, 29,
             21, 13, 5, 28, 20, 12, 4
        };
        private readonly int[] PC2 =
        {
             14, 17, 11, 24, 1, 5,
             3, 28, 15, 6, 21, 10,
             23, 19, 12, 4, 26, 8,
             16, 7, 27, 20, 13, 2,
             41, 52, 31, 37, 47, 55,
             30, 40, 51, 45, 33, 48,
             44, 49, 39, 56, 34, 53,
             46, 42, 50, 36, 29, 32
        };
        private readonly int[] Shifts = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 }; // for key scheduling
        private readonly int[,,] SBoxes = new int[,,]
        {
 // S1
 {
 { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
 { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
 { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
 { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 }
 },
 // S2
 {
 { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
 { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
 { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
 { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 }
 },
 // S3
 {
 { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
 { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
 { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
 { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 }
 },
 // S4
 {
 { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
 { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
 { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
 { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }
 },
 // S5
 {
 { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
 { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
 { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
 { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }
 },
 // S6
 {
 { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
 { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
 { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
 { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }
 },
 // S7
 {
 { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
 { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
 { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
 { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }
 },
 // S8
 {
 { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
 { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
 { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
 { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
 }
        };
        private readonly byte[][] WeakKeys = new byte[][]
        {
 [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01],
 [0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE],
 [0x1F, 0x1F, 0x1F, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E],
 [0xE0, 0xE0, 0xE0, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1]
        };
        private readonly byte[][] SemiWeakKeyPairs = new byte[][]
        {
 [0x01, 0x1F, 0x01, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E],
 [0xFE, 0xE0, 0xFE, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1],
 [0x01, 0xE0, 0x01, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1],
 [0xFE, 0x1F, 0xFE, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E],
 [0x1F, 0xE0, 0x1F, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1],
 [0xE0, 0x1F, 0xE0, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E],
 [0x01, 0xFE, 0x01, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE],
 [0xFE, 0x01, 0xFE, 0x01, 0x01, 0x01, 0x01, 0x01],
 [0x1F, 0xE0, 0x1F, 0xFE, 0xE0, 0xE0, 0xE0, 0xE0],
 [0xE0, 0x1F, 0xE0, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F]
        };
        #endregion
        public DesViewModel Encrypt(DesRequestViewModel viewModel)
        {
            byte[] inputBytes = Encoding.UTF8.GetBytes(viewModel.InputText);
            byte[] keyBytes = Encoding.UTF8.GetBytes(viewModel.Key);
            byte[] validKey = ValidateAndPadKey(keyBytes);
            var res = Encrypt(PadInput(inputBytes, 8), validKey);
            return res;
        }
        public DesViewModel Decrypt(DesRequestViewModel viewModel)
        {
            byte[] inputBytes = Convert.FromBase64String(viewModel.InputText);
            byte[] keyBytes = Encoding.UTF8.GetBytes(viewModel.Key);
            byte[] validKey = ValidateAndPadKey(keyBytes);
            var result = Decrypt(inputBytes, validKey);
            result.ResultText = UnpadOutput(result.ResultText);
            return result;
        }
        private string UnpadOutput(string input)
        {
            var output = Regex.Replace(input, @"[^\u0020-\u007E]", "*");
            var index = output.IndexOf('*');
            if (index >= 0)
                output = output.Substring(0, index);
            return output;
        }
        private byte[] ValidateAndPadKey(byte[] key)
        {
            if (key.Length > BlockSizeInBytes)
                throw new ArgumentException("Key must be 8 bytes long.");
            if (key.Length < BlockSizeInBytes)
            {
                var paddedKey = new byte[8];
                Array.Copy(key, paddedKey, key.Length);
                return paddedKey;
            }
            return key;
        }
        private DesViewModel Encrypt(byte[] input, byte[] key)
        {
            return Process(input, key, isEncrypt: true);
        }
        private DesViewModel Decrypt(byte[] input, byte[] key)
        {
            return Process(input, key, isEncrypt: false);
        }
        private DesViewModel Process(byte[] input, byte[] key, bool isEncrypt)
        {
            if (IsWeakKey(key))
                throw new ArgumentException("Weak key detected.");
            int blockSize = 8;
            byte[] paddedInput = PadInput(input, blockSize);
            var entropyBefore = new List<double>();
            var entropyAfter = new List<double>();
            var outputBytes = new List<byte>();
            for (int blockIndex = 0; blockIndex < paddedInput.Length; blockIndex += blockSize)
            {
                byte[] block = new byte[blockSize];
                Array.Copy(paddedInput, blockIndex, block, 0, blockSize);
                byte[] permutedInput = Permute(block, InitialPermutation);
                var left = BitConverter.ToUInt32(permutedInput, 0);
                var right = BitConverter.ToUInt32(permutedInput, 4);
                var roundKeys = GenerateRoundKeys(key);
                if (!isEncrypt)
                    Array.Reverse(roundKeys);
                for (var i = 0; i < NumRounds; i++)
                {
                    entropyBefore.Add(CalculateEntropy(right));
                    var roundResult = RoundFunction(right, roundKeys[i]);
                    var newRight = left ^ roundResult;
                    left = right;
                    right = newRight;
                    entropyAfter.Add(CalculateEntropy(right));
                }
                byte[] preOutput = BitConverter.GetBytes(right).Concat(BitConverter.GetBytes(left)).ToArray();
                byte[] outputBlock = Permute(preOutput, FinalPermutation);
                outputBytes.AddRange(outputBlock);
            }
            var viewModel = new DesViewModel
            {
                EntropyBefore = entropyBefore,
                EntropyAfter = entropyAfter,
                ResultText = isEncrypt
                ? Convert.ToBase64String(outputBytes.ToArray()) 
                : Encoding.UTF8.GetString(outputBytes.ToArray()),
            };
            return viewModel;
        }
        private byte[] PadInput(byte[] input, int blockSize)
        {
            int paddingSize = blockSize - (input.Length % blockSize);
            byte[] paddedInput = new byte[input.Length + paddingSize];
            Array.Copy(input, paddedInput, input.Length);
            for (int i = input.Length; i < paddedInput.Length; i++)
            {
                paddedInput[i] = (byte)paddingSize;
            }
            return paddedInput;
        }
        private uint RoundFunction(uint right, byte[] roundKey)
        {
            byte[] expandedRight = Permute(BitConverter.GetBytes(right),
           ExpansionTable);
            byte[] xorResult = Xor(expandedRight, roundKey);
            byte[] substituted = Substitution(xorResult);
            byte[] permuted = Permute(substituted, PBoxPermutation);
            return BitConverter.ToUInt32(permuted, 0);
        }
        private byte[][] GenerateRoundKeys(byte[] key)
        {
            byte[] permutedKey = Permute(key, PC1);
            var (left, right) = SplitKeyIntoHalves(permutedKey);
            var roundKeys = new byte[NumRounds][];
            for (int i = 0; i < NumRounds; i++)
            {
                int shiftAmount = (i == 0 || i == 1 || i == 8 || i == 15) ?
               1 : 2;
                left = LeftCircularShift(left, shiftAmount, HalfKeySize);
                right = LeftCircularShift(right, shiftAmount, HalfKeySize);
                byte[] combinedKey = BitConverter.GetBytes((left <<
               HalfKeySize) | right);
                roundKeys[i] = Permute(combinedKey, PC2);
            }
            return roundKeys;
        }
        private (uint left, uint right) SplitKeyIntoHalves(byte[] permutedKey)
        {
            if (permutedKey.Length != KeySize / BlockSizeInBytes)
                throw new ArgumentException("Permuted key must be 7 bytes long.");
               
                uint left = 0;
            for (int i = 0; i < 4; i++)
                left |= (uint)permutedKey[i] << (24 - (i * BlockSizeInBytes));
            left >>= 4;
            uint right = 0;
            for (int i = 4; i < 7; i++)
                right |= (uint)permutedKey[i] << (24 - ((i - 4) *
               BlockSizeInBytes));
            right >>= 4;
            return (left, right);
        }
        private double CalculateEntropy(uint bits)
        {
            int countOfOnes = 0;
            for (int i = 0; i < EntropyBits; i++)
                countOfOnes += (int)((bits >> i) & 1);
            var p = (double)countOfOnes / EntropyBits;
            return -p * Math.Log2(p) - (1 - p) * Math.Log2(1 - p);
        }
        private bool IsWeakKey(byte[] key)
        {
            foreach (var weakKey in WeakKeys)
            {
                if (weakKey.SequenceEqual(key))
                    return true;
            }
            for (int i = 0; i < SemiWeakKeyPairs.Length; i += 2)
            {
                if (SemiWeakKeyPairs[i].SequenceEqual(key)
                || SemiWeakKeyPairs[i + 1].SequenceEqual(key))
                {
                    return true;
                }
            }
            return false;
        }
        private byte[] Permute(byte[] input, int[] permutationTable)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));
            if (permutationTable == null)
                throw new ArgumentNullException(nameof(permutationTable));
            int bitLength = permutationTable.Length;
            int byteLength = (bitLength + 7) / BlockSizeInBytes;
            var output = new byte[byteLength];
            var inputBits = new bool[BlockSize];
            for (int i = 0; i < input.Length * BlockSizeInBytes; i++)
            {
                int byteIndex = i / BlockSizeInBytes;
                int bitIndex = i % BlockSizeInBytes;
                inputBits[i] = (input[byteIndex] & (1 << (7 - bitIndex))) !=
               0;
            }
            for (int i = 0; i < bitLength; i++)
            {
                int bitIndex = permutationTable[i] - 1;
                int outputByteIndex = i / BlockSizeInBytes;
                int outputBitOffset = i % BlockSizeInBytes;
                if (inputBits[bitIndex])
                    output[outputByteIndex] |= (byte)(1 << (7 -
                   outputBitOffset));
            }
            return output;
        }
        private byte[] Xor(byte[] a, byte[] b)
        {
            var result = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
                result[i] = (byte)(a[i] ^ b[i]);
            return result;
        }
        private byte[] Substitution(byte[] input)
        {
            var output = new byte[4];
            for (int i = 0; i < BlockSizeInBytes; i++)
            {
                int sixBits = (input[i / 2] >> (4 * (1 - (i % 2)))) & 0x3F;
                int row = ((sixBits & 0x20) >> 4) | (sixBits & 0x01);
                int col = (sixBits >> 1) & 0x0F;
                int sboxValue = SBoxes[i, row, col];
                if (i % 2 == 0)
                    output[i / 2] = (byte)(sboxValue << 4);
                else
                    output[i / 2] |= (byte)sboxValue;
            }
            return output;
        }
        private uint LeftCircularShift(uint value, int shift, int size)
        {
            return (value << shift) | (value >> (size - shift));
        }

    }
}
