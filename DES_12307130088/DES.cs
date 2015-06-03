using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DES_12307130088
{
    class DES
    {

        #region Constant Matrices
        //matrix IP
        readonly byte[] IP_Table = new byte[64] 
        {
            57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
            56, 48, 40, 32, 24, 16, 8, 0, 58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6
        };
        //matrix IP^-1
        readonly byte[] IP_1_Table = new byte[64]
        {
            39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24
        };
        //matrix E
        readonly byte[] E_Table = new byte[48]
        {
            31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9, 10,
            11, 12, 11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 20,
            21, 22, 23, 24, 23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0
        };
        //matrix P
        readonly byte[] P_Table = new byte[32]
        {
            15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9,
            1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24
        };
        //matrix Rotate_Left
        readonly byte[] Rotate_Table = new byte[16]
        {
            1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
        };
        //S Box
        readonly byte[, ,] S_Box = new byte[8, 4, 16]
        {
            {   // S0
                {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
            },
            {	// S1
                {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
		        {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
		        {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
            },
            {   // S2
                {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
		        {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
		        {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
		        {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
            },
            {   // S3
		        {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
		        {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
		        {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
		        {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
            },
		    {   // S4
		        {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
		        {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
		        {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
		        {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
            },
		    {   // S5
                {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
		        {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
		        {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
		        {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
            },
		    {   // S6
                {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
		        {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
		        {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
		        {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
            },
		    {   // S7
                {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
		        {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
		        {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
		        {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
            }
        };
        //matrix IPC
        readonly byte[] IPC_Table = new byte[56]
        {
            56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17,
            9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35,
            62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
            13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3
        };
        //matrix PC
        readonly byte[] PC_Table = new byte[48]
        {
            13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3, 
            25, 7, 15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46, 54, 29, 39, 
            50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
        };
        #endregion

        /*基本数据结构：采用byte型数组存储二进制串，虽耗费空间，但有利于进行下标置换操作*/

         //ToBinstr函数功能：将Uint64类型的64位整数转化为64位二进制字符串
        string ToBinStr(UInt64 u)
        {
            char[] s = new char[64];
            for (int i = 63; i >= 0; i--)
            {
                s[i] = (u & 1) == 1 ? '1' : '0';
                u >>= 1;
            }
            return new string(s);
        }

        //PC_Trans：PC下标置换
        byte[] PC_Trans(byte[] m)
        {
            int i;
            byte[] temp = new byte[48];
            for (i = 0; i < 48; i++)
            {
                temp[i] = m[PC_Table[i]];
            }
            return temp;
        }

        //IPC_Trans：IPC下标置换
        byte[] IPC_Trans(byte[] m)
        {
            int i;
            byte[] temp = new byte[56];
            for (i = 0; i < 56; i++)
            {
                temp[i] = m[IPC_Table[i]];
            }
            return temp;
        }

        //IP_Trans：根据矩阵IP初始下表置换
        byte[] IP_Trans(byte[] m)
        {
            int i;
            byte[] temp = new byte[64];
            for (i = 0; i < 64; i++)
            {
                temp[i] = m[IP_Table[i]];
            }
            return temp;
        }

        //IP_1_Trans：根据矩阵IP^-1下表置换
        byte[] IP_1_Trans(byte[] m)
        {
            int i;
            byte[] temp = new byte[64];
            for (i = 0; i < 64; i++)
            {
                temp[i] = m[ IP_1_Table[i] ];
            }
            return temp;
        }

        //E_Trans：根据矩阵E放大换位
        byte[] E_Trans(byte[] m)
        {
            int i;
            byte[] temp = new byte[48];
            for (i = 0; i < 48; i++)
            {
                temp[i] = m[ E_Table[i] ];
            }
            return temp;
        }

        //P_Trans：根据矩阵P单纯换位
        byte[] P_Trans(byte[] m)
        {
            int i;
            byte[] temp = new byte[32];
            for (i = 0; i < 32; i++)
            {
                temp[i] = m[P_Table[i]];
            }
            return temp;
        }

        //SBOX_Trans：S盒置换
        byte[] SBOX_Trans(int n, byte[] m)
        {
            int i;
            int row = (m[0] << 1) | m[5];
            int column = (m[1] << 3) | (m[2] << 2) | (m[3] << 1) | m[4];
            int num = S_Box[n, row, column];
            byte[] temp = new byte[4];
            for (i = 3; i >= 0; i--)
            {
                temp[i] = (byte)(num % 2);
                num /= 2;
            }
            return temp;
        }

        //RotateLeft：根据Rotate_Table循环左移秘钥
        byte[] RotateLeft(int n, byte[] m)
        {
            int i;
            byte[] temp = new byte[28];
            for (i = 0; i < 28; i++)
            {
                temp[( i - Rotate_Table[n] + 28) % 28 ] = m[i];
            }
            return temp;
        }

        //RoundFunction：轮函数F
        byte[] RoundFunction(byte[] m, byte[,] k, int n)
        {
            int i, j;
            byte[] Exp = new byte[48];
            byte[] in6 = new byte[6];
            byte[] out4 = new byte[4];
            byte[] step = new byte[48];
            byte[] result = new byte[48];
            Exp = E_Trans(m);
            for (i = 0; i < 48; i++)
            {
                Exp[i] ^= k[n, i];
            }
            for (i = 0; i < 8; i++)
            {
                for (j = 0; j < 6; j++)
                {
                    in6[j] = Exp[6 * i + j];
                }
                out4 = SBOX_Trans(i, in6);
                for (j = 0; j < 4; j++)
                {
                    step[4 * i + j] = out4[j];
                }
            }
            result = P_Trans(step);
            return result;
        }

        //MakeSubKeys：生成子秘钥
        byte[,] MakeSubKeys(byte[] KEY)
        {
            int i, j;
            byte[,] SubKeys = new byte[6, 48];
            byte[] SubKey = new byte[48];
            byte[] out56 = new byte[56]; 
            byte[] ValidKey = IPC_Trans(KEY);
            byte[] c = new byte[28];
            byte[] d = new byte[28];
            for (j = 0; j<28; j++)
            {
                c[j] = ValidKey[j];
                d[j] = ValidKey[28 + j];
            }
            for (i = 0; i < 6; i++)
            {
                c = RotateLeft(i, c);
                d = RotateLeft(i, d);
                for (j = 0; j < 28; j++)
                {
                    out56[j] = c[j];
                    out56[28 + j] = d[j];
                }
                SubKey = PC_Trans(out56);
                for (j = 0; j < 48; j++)
                {
                    SubKeys[i, j] = SubKey[j];
                }
            }
            return SubKeys;
        }

        //CBC：将lastCrypt, thisPlain按位异或
        public byte[] CBC(byte[] lastCrypt, byte[] thisPlain)
        {
            int i;
            byte[] temp = new byte[64];
            for (i = 0; i < 64; i++)
            {
                temp[i] = (byte)(lastCrypt[i] ^ thisPlain[i]);
            }
            return temp;
        }

        //DES_Encrypt64：由主密钥KEY和64bit明文m（使用Byte数组存储）进行DES加密
        byte[] DES_Encrypt64(byte[] KEY, byte[] m)
        {
            int round, i;
            byte[] temp = new byte[64];
            byte[] result = new byte[64];
            byte[] L = new byte[32];
            byte[] R = new byte[32];
            byte[] RTemp = new byte[32];
            byte[] RoundTemp = new byte[32]; 
            byte[,] SubKeys = new byte[6, 48];
            SubKeys = MakeSubKeys(KEY);
            temp = IP_Trans(m);
            for (i = 0; i < 32; i++)
            {
                L[i] = temp[i];
                R[i] = temp[32 + i];
            }
            for (round = 0; round < 6; round++) 
            {               
                R.CopyTo(RTemp, 0);
                RoundTemp = RoundFunction(R, SubKeys, round);
                for (i = 0; i < 32; i++)
                {
                    R[i] = (byte)(L[i] ^ RoundTemp[i]);
                }
                RTemp.CopyTo(L, 0);
            }
            for (i = 0; i < 32; i++)
            {
                temp[i] = L[i];
                temp[32 + i] = R[i];
            }
            result = IP_1_Trans(temp);
            return result;
        }

        //DES_Decrypt64：由主密钥KEY和64bit秘文m（使用Byte数组存储）进行DES解密
        byte[] DES_Decrypt64(byte[] KEY, byte[] m)
        {
            int round, i;
            byte[] temp = new byte[64];
            byte[] result = new byte[64];
            byte[] L = new byte[32];
            byte[] R = new byte[32];
            byte[] LTemp = new byte[32];
            byte[] RoundTemp = new byte[32];
            byte[,] SubKeys = new byte[6, 48];
            SubKeys = MakeSubKeys(KEY);
            temp = IP_Trans(m);
            for (i = 0; i < 32; i++)
            {
                L[i] = temp[i];
                R[i] = temp[32 + i];
            }
            for (round = 5; round >= 0; round--)
            {
                L.CopyTo(LTemp, 0);
                RoundTemp = RoundFunction(L, SubKeys, round);
                for (i = 0; i < 32; i++)
                {
                    L[i] = (byte)(R[i] ^ RoundTemp[i]);
                }
                LTemp.CopyTo(R, 0);
            }
            for (i = 0; i < 32; i++)
            {
                temp[i] = L[i];
                temp[32 + i] = R[i];
            }
            result = IP_1_Trans(temp);
            return result;
        }

        //DES_Encrypt：由主密钥KEY、初始向量IV和已经过Padding的明文二进制字符串进行DES加密
        public string DES_Encrypt(byte[] KEY, byte[] IV, string content)
        {
            string result;
            result = "";
            int i, block;
            byte[] m = new byte[64];
            byte[] crypt = new byte[64];
            IV.CopyTo(crypt, 0);
            for (block = 0; block < content.Length / 64; block++)
            {
                string content64 = content.Substring(block * 64, 64);
                for (i = 0; i < 64; i++)
                {
                    m[i] = (byte)(content64[i] - '0');
                }
                crypt = DES_Encrypt64(KEY, CBC(crypt, m));
                UInt64 a = 0;
                for (i = 0; i < 64; i++)
                {
                    a = (a << 1) + (UInt64)(crypt[i] & 1);
                }
                result += ToBinStr(a);
            }
            return result;
        }

        //DES_Decrypt：由主密钥KEY、初始向量IV和秘文二进制字符串进行DES解密（不做Depadding处理）
        public string DES_Decrypt(byte[] KEY, byte[] IV, string content)
        {
            string result;
            result = "";
            int i, block;
            byte[] m = new byte[64];
            byte[] crypt = new byte[64];
            byte[] cryptLast = new byte[64];
            IV.CopyTo(cryptLast, 0);
            for (block = 0; block < content.Length / 64; block++)
            {
                string content64 = content.Substring(block * 64, 64);
                for (i = 0; i < 64; i++)
                {
                    crypt[i] = (byte)(content64[i] - '0');
                }
                m = DES_Decrypt64(KEY, crypt);
                m = CBC(cryptLast, m);
                crypt.CopyTo(cryptLast, 0);
                UInt64 a = 0;
                for (i = 0; i < 64; i++)
                {
                    a = (a << 1) + (UInt64)(m[i] & 1);
                }
                result += ToBinStr(a);
            }
            return result;
        }
    }
};