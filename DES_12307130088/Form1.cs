using System;
using System.IO;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace DES_12307130088
{
    public partial class Form1 : Form
    {
        string content;
        string result;
        string dir;
        byte[] KEY = new byte[64];
        byte[] IV = new byte[64];
        bool File_Confirm, IV_Confirm, KEY_Confirm;
        DES new_des = new DES();

        public Form1()
        {
            InitializeComponent();
            File_Confirm = IV_Confirm = KEY_Confirm = false;    //文件已加载、IV已加载、KEY已加载三个标志初始化为false
        }

        //binCheck函数功能：检验64位字符串是否为二进制字符串，是则返回true，否则返回false
        bool binCheck(string s)
        {
            int i;
            int len = s.Length;
            for (i = 0; i < len; i++)
            {
                if (s[i] != '0' && s[i] != '1')
                    return false;
            }
            return true;
        }

        /*
         * Padding0函数功能：按zeros方法填充待加密串，即全填0直至长度为64倍数，已换用更好的Padding机制
         * string Padding0(string s)
         * {
         * int i;
         * int len = s.Length;
         * if (len % 64 == 0)
         * return s;
         * else
         * {
         * int pd = ((int)(s.Length / 64) + 1) * 64 - s.Length;
         * for (i = 0; i < pd; i++)
         * {
         * s += '0';
         * }
         * }
         * return s;
         * }
         */

        //Padding_PKCS5函数功能：按照PKCS#5标准方法进行待加密串填充。
        //PKCS#5标准方法：填充相同的字节，且该字节的值就是要填充的字节数，恰好8个字节需补8个字节的0x08
        string Padding_PKCS5(string s)
        {
            int i, pd, j;
            int len = s.Length;
            pd = 8 - (int)((s.Length % 64) / 8);
            string pdstr = Convert.ToString(pd, 2);
            for (i = 0; i < pd; i++) 
            {
                for (j = 0; j < 8 - pdstr.Length; j++)
                {
                    s += '0';
                }
                s += pdstr;
            }
            return s;
        }

        //Depadding_PKCS5函数功能：按照PKCS#5标准方法将已解密串进行去填充化。
        string Depadding_PKCS5(string s)
        {
            int i, pd = 0;
            string str = s.Substring(s.Length - 8);
            for (i = 0; i < 8; i++)
            {
                pd = (pd << 1) + ((str[i]-'0') & 1);
            }
            if (pd > 8)
            {
                MessageBox.Show("待解密文件、主密钥或初始向量有误，无法进行正确解密，请检查后重新加载!");
                content = "";
                File_Confirm = KEY_Confirm = IV_Confirm = false;
                label6.ForeColor = Color.Red;
                label6.Text = "文件未读取";
                return "";
            }
            return s.Substring(0, s.Length - pd * 8);
        }

        //Random64函数功能：生成随机的64位二进制字符串
        string Random64()
        {
            int i;
            string s="";
            Random rnd = new Random();
            for (i = 0; i < 64; i++)
            {
                s += rnd.Next(2);
            }
            return s;
        }
        
        //button1：加载文件按钮
        private void button1_Click(object sender, EventArgs e)
        {
            OpenFileDialog file = new OpenFileDialog();
            file.Filter = "txt files (*.txt)|*.txt|All files (*.*)|*.*";
            file.InitialDirectory = Application.StartupPath;
            file.ShowReadOnly = true;
            DialogResult r = file.ShowDialog();
            if (r == DialogResult.OK)
            {
                string filename = file.FileName;
                dir = System.IO.Path.GetDirectoryName(filename);
                FileStream aFile = new FileStream(filename, FileMode.Open, FileAccess.Read);
                StreamReader sr = new StreamReader(aFile);
                sr.BaseStream.Seek(0, SeekOrigin.Begin);
                content = sr.ReadToEnd();
                sr.Close();
                aFile.Close();
                if (content.Length % 8 != 0)
                {
                    MessageBox.Show("二进制文件未按字节（8 bit）对齐，请进行修改并重新选择文件");
                    content = "";
                    return;
                }
                if (!binCheck(content))
                {
                    MessageBox.Show("文件不符合二进制要求，请进行修改并重新选择文件");
                    content = "";
                    return;
                }
                File_Confirm = true;
                label6.ForeColor = Color.Blue;
                label6.Text = "文件" +filename+"读取成功";
            }
        }

        //button2：主密钥确认按钮
        private void button2_Click(object sender, EventArgs e)
        {
            string k = textBox1.Text;
            if (k.Length != 64 || !binCheck(k)) 
            {
                MessageBox.Show("主秘钥不符合规范，应为64位二进制串");
                return;
            }
            for (int i = 0; i < 64; i++)
            {
                KEY[i] = (byte)(k[i] - '0');
            }
            KEY_Confirm = true;
            label2.ForeColor = Color.Blue;
            label2.Text = "主密钥已确认";
        }

        //button3：初始向量确认按钮
        private void button3_Click(object sender, EventArgs e)
        {
            string ivs = textBox2.Text;
            if (ivs.Length != 64 || !binCheck(ivs)) 
            {
                MessageBox.Show("初始向量不符合规范，应为64位二进制串");
                return;
            }
            for (int i = 0; i < 64; i++)
            {
                IV[i] = (byte)(ivs[i] - '0');
            }
            IV_Confirm = true;
            label4.ForeColor = Color.Blue;
            label4.Text = "初始向量已确认";
        }

        //button4：逐64bit进行CBC密码分组模式的DES加密，并写入同一目录的文件CRYTOGRAM.txt
        private void button4_Click(object sender, EventArgs e)
        {
            if (!File_Confirm)
            {
                MessageBox.Show("文件未读取!");
                return;
            }
            if (!KEY_Confirm)
            {
                MessageBox.Show("主密钥未确认!");
                return;
            }
            if (!IV_Confirm)
            {
                MessageBox.Show("初始向量未确认!");
                return;
            }
            content = Padding_PKCS5(content);
            result = new_des.DES_Encrypt(KEY, IV, content);
            if (File.Exists(dir + @"\CRYPTOGRAM.txt")) 
            {
                File.Delete(dir+@"\CRYPTOGRAM.txt");
            }
            FileStream bFile = new FileStream(dir+@"\CRYPTOGRAM.txt", FileMode.CreateNew);
            StreamWriter sw = new StreamWriter(bFile);
            sw.Write(result);
            sw.Close();
            bFile.Close();
            DialogResult dr;
            dr = MessageBox.Show("加密完成！！", "DES");
            if (dr == System.Windows.Forms.DialogResult.OK)
            {
                File_Confirm = IV_Confirm = KEY_Confirm = false;
                content = "";
                label6.ForeColor = Color.Red;
                label6.Text = "文件未读取";
                System.Diagnostics.Process.Start("notepad.exe", dir + @"\CRYPTOGRAM.txt");
            }
        }

        //button5：逐64bit进行CBC密码分组模式的DES解密，并写入同一目录的文件SOURCE.txt
        private void button5_Click(object sender, EventArgs e)
        {
            if (!File_Confirm)
            {
                MessageBox.Show("文件未读取!");
                return;
            }
            if (!KEY_Confirm)
            {
                MessageBox.Show("主密钥未确认!");
                return;
            }
            if (!IV_Confirm)
            {
                MessageBox.Show("初始向量未确认!");
                return;
            }
            if (content.Length % 64 != 0)
            {
                MessageBox.Show("待解密文件长度有误，应为64bit的倍数，请检查后重新加载!");
                content = "";
                File_Confirm = false;
                label6.ForeColor = Color.Red;
                label6.Text = "文件未读取";
                return;
            }
            result = new_des.DES_Decrypt(KEY, IV, content);
            result = Depadding_PKCS5(result);
            if (result != "")
            {
                if (File.Exists(dir + @"\SOURCE.txt"))
                {
                    File.Delete(dir + @"\SOURCE.txt");
                }
                FileStream bFile = new FileStream(dir + @"\SOURCE.txt", FileMode.CreateNew);
                StreamWriter sw = new StreamWriter(bFile);
                sw.Write(result);
                sw.Close();
                bFile.Close();
                DialogResult dr;
                dr = MessageBox.Show("解密完成！！", "DES");
                if (dr == System.Windows.Forms.DialogResult.OK)
                {
                    File_Confirm = IV_Confirm = KEY_Confirm = false;
                    content = "";
                    label6.ForeColor = Color.Red;
                    label6.Text = "文件未读取";
                    System.Diagnostics.Process.Start("notepad.exe", dir + @"\SOURCE.txt");
                }
            }
        }

        //button6：随机生成主密钥KEY
        private void button6_Click(object sender, EventArgs e)
        {
            KEY_Confirm = false;
            textBox1.Text = Random64();
        }

        //button7：随机生成初始向量IV
        private void button7_Click(object sender, EventArgs e)
        {
            IV_Confirm = false;
            textBox2.Text = Random64();
        }
        
        //timer1：时钟，时刻保持label2，label4内容（输入的主密钥长度、初始向量长度）
        private void timer1_Tick(object sender, EventArgs e)
        {
            if (!KEY_Confirm)
            {
                if (textBox1.TextLength !=64)
                    label2.ForeColor = Color.Red;
                else
                    label2.ForeColor = Color.Green;
                label2.Text = textBox1.TextLength.ToString();
            }
            if (!IV_Confirm)
            {
                if (textBox2.TextLength != 64)
                    label4.ForeColor = Color.Red;
                else
                    label4.ForeColor = Color.Green;
                label4.Text = textBox2.TextLength.ToString();
            }
        }
    }
}
