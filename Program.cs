using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace drupal_pass
{
    class DrupalHash
    {
        string itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        int min_log = 7;
        int max_log = 30;
        int default_log = 15;
        int hash_length = 55;

        int password_get_count_log2(string setting)
        {
            return itoa64.IndexOf(setting.ToCharArray()[3]);
        }

        string custom64(byte[] bytes, int count = 0)
        {
            if (count == 0)
                count = bytes.Length;
            string output = "";
            int i = 0;
            while (true)
            {
                byte value = bytes[i];
                i += 1;
                output += itoa64[value & 0x3f];
                if (i < count)
                    value |= (byte)(bytes[i] << 8);
                output += itoa64[(value >> 6) & 0x3f];
                if (i >= count)
                    break;
                i += 1;
                if (i < count)
                    value |= (byte)(bytes[i] << 16);
                output += itoa64[(value >> 12) & 0x3f];
                if (i >= count)
                    break;
                i += 1;
                output += itoa64[(value >> 18) & 0x3f];
                if (i >= count)
                    break;
            }
            return output;
        }


        string password_crypt(string password, string setting)
        {
            string _setting = setting.Substring(0, 12);
            if (_setting[0] != '$' || _setting[2] != '$')
                return null;

            int count_log2 = password_get_count_log2(setting);
            string salt = _setting.Substring(4, 8);
            if (salt.Length < 8)
                return null;
            int count = 1 << count_log2;
            SHA512 shaM = new SHA512Managed();
            Encoding unicode = new UnicodeEncoding(true, false);
            byte[] data = unicode.GetBytes(salt + password);
            byte[] pass = unicode.GetBytes(password);
            byte[] hash = shaM.ComputeHash(data);
            for (int c = 0; c < count; c++)
            {
                data = new byte[hash.Length + pass.Length];
                hash.CopyTo(data, 0);
                pass.CopyTo(data, hash.Length);
                hash = shaM.ComputeHash(data);
            }
            string output = setting + custom64(hash);
            return output.Substring(0, hash_length);
        }

        string password_generate_salt(int count_log2)
        {
            string output = "$S$";
            count_log2 = password_enforce_log2_boundaries(count_log2);
            output += itoa64[count_log2];
            Random rnd = new Random();
            byte[] rand = new byte[6];
            rnd.NextBytes(rand);
            output += custom64(rand, 6);
            return output;
        }

        int password_enforce_log2_boundaries(int count_log2)
        {
            if (count_log2 < min_log)
                return min_log;
            if (count_log2 > max_log)
                return max_log;
            return count_log2;
        }

        public string hash_password(string password, int count_log2 = 0)
        {
            if (count_log2 == 0)
                count_log2 = default_log;
            string salt = password_generate_salt(count_log2);
            return password_crypt(password, salt);
        }

        public bool check_password(string password, string stored_hash)
        {
            string hash = password_crypt(password, stored_hash);
            return (!String.IsNullOrEmpty(hash) && stored_hash == hash);
        }
    }

    class Program
    {

        static void Main(string[] args)
        {
            string pass = "123";
            string hash =     "$S$D6JLBnMLMLwWhyktl0Os9f50zd2PGVneKdeYVv7jQtCt4VXQgssz";
            string bad_hash = "$S$D7JLBnMLMLwWhyktl0Os9f50zd2PGVneKdeYVv7jQtCt4VXQgsss";
            DrupalHash drp = new DrupalHash();
            //string new_hash = drp.hash_password(pass);
            //Console.WriteLine("hash=" + new_hash);
            Console.WriteLine("check " + bad_hash + ": " + drp.check_password("123", bad_hash).ToString());
            //Console.WriteLine("check " + new_hash + ": " + drp.check_password("123", new_hash).ToString());
            //Console.WriteLine("check " + hash + ": " + drp.check_password("123", hash).ToString());
            
            Console.ReadKey();
        }
    }
}
