/* this file is part of BurnOut
*Copyright (C)2005-2010 Gernot Knippen
 * Copyright (C) 2018 Natalia Portillo
*
*This program is free software; you can redistribute it and/or
*modify it under the terms of the GNU General Public License
*as published by the Free Software Foundation; either
*version 2 of the License, or (at your option) any later version.
*
*This program is distributed in the hope that it will be useful,
*but WITHOUT ANY WARRANTY; without even the implied warranty of
*MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
*GNU General Public License for more details.
*
*You can get a copy of the GNU General Public License
*by writing to the Free Software
*Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

using System;
using System.IO;
using System.Linq;
using System.Text;

namespace BurnOutSharp
{
    static class BurnOut
    {
        public const int Filesizelimit = 20971520;

        public static void Main(string[] args)
        {
            bool advancedscan = false;

            Console.WriteLine("BurnOut " + typeof(BurnOut).Assembly.GetName().Version);
            Console.WriteLine("© 2005-2010, Gernot Knippen alias GF7");
            Console.WriteLine("© 2018, Natalia Portillo");
            
            for(int i = 0; i < args.Length; i++)
            {
                if(args[i].ToLower() == "/?" || args[i].ToLower() == "/help" || args[i].ToLower() == "-?" ||
                   args[i].ToLower() == "--help")
                {
                    Console.WriteLine("usage: BurnOut.exe [-advancedscan] [-scan Filename/Drive]");
                    return;
                }

                if(args[i].ToLower() == "-advancedscan" || args[i] == "/advancedscan")
                    advancedscan = true;
                else if(args[i].ToLower() == "-scan" || args[i] == "/scan")
                {
                    string strprotection;
                    if(Directory.Exists(args[i + 1]))
                        {
                            Console.WriteLine("Scanning "              + args[i + 1]);
                            strprotection = ProtectionFind.Scan(args[i + 1], advancedscan);
                            if(!string.IsNullOrEmpty(strprotection)) Console.WriteLine(strprotection);
                            else if(ProtectionFind.IsCdCheck)
                                Console.WriteLine("could be " + "CD/DVD-Check");
                            else if(ProtectionFind.IsDummyfiles)
                                Console.WriteLine("could be " + "Dummyfiles");
                        }
                        else if(File.Exists(args[i + 1]))
                        {
                            Console.WriteLine("Scanning "                    + args[i + 1]);
                            strprotection = ProtectionFind.ScaninFile(args[i + 1], advancedscan);
                            if(!string.IsNullOrEmpty(strprotection)) Console.WriteLine(strprotection);
                            else if(ProtectionFind.IsCdCheck)
                                Console.WriteLine("could be " + "CD/DVD-Check");
                        }
                        else
                            Console.WriteLine("Directory/File does not exist!");

                    return;
                }
            }
        }

        public static string[] GetAllFiles(string path, string filter = "*")
        {
            string[] files;
            string[] tempfilter = filter.Split('|');
            try
            {
                files = Directory.GetFiles(path, tempfilter[0]);
                string[] newfiles;
                int      i;
                if(tempfilter.Length > 1)
                    for(i = 1; i     < tempfilter.Length; i++)
                    {
                        newfiles = Directory.GetFiles(path, tempfilter[i]);
                        files    = files.Concat(newfiles).ToArray();
                    }

                string[] directories = Directory.GetDirectories(path);
                for(i = 0; i < directories.Length; i++)
                {
                    newfiles                   = GetAllFiles(directories[i], filter);
                    if(newfiles != null) files = files.Concat(newfiles).ToArray();
                }
            }
            catch(Exception ex)
            {
                Console.WriteLine(ex.ToString());
                return null;
            }

            return files;
        }

        public static int FileExists(string filename, FileInfo[] files)
        {
            int i;
            filename = filename.ToLower();
            for(i = 0; i                   <= files.Length - 1; i++)
                if(files[i].Name.ToLower() == filename)
                    return i;

            return -1;
        }

        public static int PrefixInArray(byte[] string1, byte[] string2, byte[] prefix1, byte[] prefix2)
        {
            int rtn = 0;
            while(rtn != -1)
            {
                rtn = InArray(string1, string2, rtn + 1);
                if(rtn == -1) continue;

                byte[] sub1 = new byte[prefix1.Length];
                Array.Copy(string1, rtn - prefix1.Length, sub1, 0, prefix1.Length);
                if(sub1.SequenceEqual(prefix1)) return rtn - prefix1.Length - 1;

                byte[] sub2 = new byte[prefix2.Length];
                Array.Copy(string1, rtn - prefix2.Length, sub2, 0, prefix2.Length);
                if(sub2.SequenceEqual(prefix2)) return rtn - prefix1.Length - 1;
            }

            return -1;
        }

        public static int SuffixInArray(byte[] string1, byte[] string2, byte[] suffix1, byte[] suffix2)
        {
            int rtn = 0;
            while(rtn != -1)
            {
                rtn = InArray(string1, string2, rtn + 1);
                if(rtn == -1) continue;

                byte[] sub1 = new byte[suffix1.Length];
                byte[] sub2 = new byte[suffix2.Length];
                Array.Copy(string1, rtn + string2.Length, sub1, 0, suffix1.Length);
                Array.Copy(string1, rtn + string2.Length, sub2, 0, suffix2.Length);
                
                if(sub1.SequenceEqual(suffix1) ||
                   sub2.SequenceEqual(suffix2)) return rtn;
            }

            return -1;
        }

        public static bool IsNumeric(byte Char)
        {
            return Char >= 0x30 && Char <= 0x39;
        }

        public static int InArray(byte[] array1, byte[] array2, int position = 0)
        {
            if(array1 == null || array2 == null) return -1;
            
            byte[] sliding = new byte[array2.Length];
            while(position + array2.Length <= array1.Length)
            {
                Array.Copy(array1, position, sliding, 0, array2.Length);
                if(sliding.SequenceEqual(array2)) return position;

                position++;
            }

            return -1;
        }
    }
}