using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using static BurnOutSharp.BurnOut;

namespace BurnOutSharp
{
    public static class ProtectionFind
    {
        public static bool IsCdCheck;
        static        bool isImpulseReactorWithoutVersion;
        static        bool isLaserLockWithoutVersion;
        static        bool isSafeDiscRemovedVersion;
        static        bool isSolidShieldWithoutVersion;
        static        bool isStarForceWithoutVersion;

        static        string secuRoMpaulversion;
        public static bool   IsDummyfiles;

        /// <summary>BoG_ *90.0&!!  Yy></summary>
        static byte[] safeDiscSignature =
        {
            0x42, 0x6F, 0x47, 0x5F, 0x20, 0x2A, 0x39, 0x30, 0x2E, 0x30, 0x26, 0x21, 0x21, 0x20, 0x20, 0x59, 0x79, 0x3E
        };
        const string SAFE_CAST_SIGNATURE = "product activation library";
        static byte[] secuRom4Signature = {0x41, 0x64, 0x64, 0x44, 0x03, 0x00, 0x00, 0x00};
        static byte[] secuRom5Signature = {202, 221, 221, 172, 3};
        /// <summary>_and_play.dll\0drm_pagui_doit</summary>
        static byte[] secuRomPaulSignature =
        {
            0x5F, 0x61, 0x6E, 0x64, 0x5F, 0x70, 0x6C, 0x61, 0x79, 0x2E, 0x64, 0x6C, 0x6C, 0x00, 0x64, 0x72, 0x6D, 0x5F,
            0x70, 0x61, 0x67, 0x75, 0x69, 0x5F, 0x64, 0x6F, 0x69, 0x74
        };
        const string CD_COPS_SIGNATURE = "CD-Cops,  ver. ";
        const string DVD_COPS_SIGNATURE = "DVD-Cops,  ver. ";
        const string VOB_PROTECT_CD_SIGNATURE = "VOB ProtectCD";
        const string SYSIPHUS_SIGNATURE = "V SUHPISYS";
        const string STAR_FORCE_SIGNATURE = ".sforce";
        const string STAR_FORCE_SIGNATURE2 = ".brick";
        static byte[] starForce5Signature   =
        {
            0x50, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x74, 0x00, 0x65, 0x00, 0x63, 0x00, 0x74, 0x00, 0x65, 0x00, 0x64, 0x00,
            0x20, 0x00, 0x4D, 0x00, 0x6F, 0x00, 0x64, 0x00, 0x75, 0x00, 0x6C, 0x00, 0x65
        };
        /// <summary>
        ///     "(c) Protection Technology" in UTF16-LE
        /// </summary>
        static byte[] starForceSignature3 =
        {
            0x28, 0x00, 0x63, 0x00, 0x29, 0x00, 0x20, 0x00, 0x50, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x74, 0x00, 0x65, 0x00,
            0x63, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x20, 0x00, 0x54, 0x00, 0x65, 0x00, 0x63, 0x00,
            0x68, 0x00, 0x6E, 0x00, 0x6F, 0x00, 0x6C, 0x00, 0x6F, 0x00, 0x67, 0x00, 0x79, 0x00
        };
        const string STAR_FORCE_SIGNATURE4 = "Protection Technology, Ltd.";
        /// <summary>
        ///     "DVM Library" in UTF16-LE
        /// </summary>
        static byte[] solidShieldSignature =
        {
            0x44, 0x00, 0x56, 0x00, 0x4D, 0x00, 0x20, 0x00, 0x4C, 0x00, 0x69, 0x00, 0x62, 0x00, 0x72, 0x00, 0x61, 0x00,
            0x72, 0x00, 0x79
        };
        const string LASER_LOCK_MARATHON_SIGNATURE = "Packed by SPEEnc V2 Asterios Parlamentas.PE";
        /// <summary>
        ///     "GetModuleHandleA\0\0\0\0GetProcAddress\0\0\0\0LoadLibraryA\0\0KERNEL32.dll\0ëy\1SNIF"
        /// </summary>
        static byte[] laserLockSignature =
        {
            0x47, 0x65, 0x74, 0x4D, 0x6F, 0x64, 0x75, 0x6C, 0x65, 0x48, 0x61, 0x6E, 0x64, 0x6C, 0x65, 0x41, 0x00, 0x00,
            0x00, 0x00, 0x47, 0x65, 0x74, 0x50, 0x72, 0x6F, 0x63, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x00, 0x00,
            0x00, 0x00, 0x4C, 0x6F, 0x61, 0x64, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x41, 0x00, 0x00, 0x4B, 0x45,
            0x52, 0x4E, 0x45, 0x4C, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C, 0x00, 0xEB, 0x79, 0x01, 0x53, 0x4E, 0x49, 0x46
        };
        /// <summary>
        ///     "LASERLOK_INIT\12LASERLOK_RUN\14LASERLOK_CHECK\15LASERLOK_CHECK2\15LASERLOK_CHECK3"
        /// </summary>
        static byte[] laserLock5Signature =
        {
            0x4C, 0x41, 0x53, 0x45, 0x52, 0x4C, 0x4F, 0x4B, 0x5F, 0x49, 0x4E, 0x49, 0x54, 0x0C, 0x4C, 0x41, 0x53, 0x45,
            0x52, 0x4C, 0x4F, 0x4B, 0x5F, 0x52, 0x55, 0x4E, 0x0E, 0x4C, 0x41, 0x53, 0x45, 0x52, 0x4C, 0x4F, 0x4B, 0x5F,
            0x43, 0x48, 0x45, 0x43, 0x4B, 0x0F, 0x4C, 0x41, 0x53, 0x45, 0x52, 0x4C, 0x4F, 0x4B, 0x5F, 0x43, 0x48, 0x45,
            0x43, 0x4B, 0x32, 0x0F, 0x4C, 0x41, 0x53, 0x45, 0x52, 0x4C, 0x4F, 0x4B, 0x5F, 0x43, 0x48, 0x45, 0x43, 0x4B,
            0x33
        };
        /// <summary>
        ///     ":\\LASERLOK\\LASERLOK.IN\0C:\\NOMOUSE.SP"
        /// </summary>
        static byte[] laserLock3Signature =
        {
            0x3A, 0x5C, 0x4C, 0x41, 0x53, 0x45, 0x52, 0x4C, 0x4F, 0x4B, 0x5C, 0x4C, 0x41, 0x53, 0x45, 0x52, 0x4C, 0x4F,
            0x4B, 0x2E, 0x49, 0x4E, 0x00, 0x43, 0x3A, 0x5C, 0x4E, 0x4F, 0x4D, 0x4F, 0x55, 0x53, 0x45, 0x2E, 0x53, 0x50
        };
        const string JO_WOOD_SIGNATURE = ".ext    ";
        /// <summary>
        ///     "kernel32.dll\0\0\0VirtualProtect"
        /// </summary>
        static byte[] joWoodSignature2 =
        {
            0x6B, 0x65, 0x72, 0x6E, 0x65, 0x6C, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C, 0x00, 0x00, 0x00, 0x56, 0x69, 0x72,
            0x74, 0x75, 0x61, 0x6C, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74
        };
        /// <summary>
        ///     "HúMETINF"
        /// </summary>
        static byte[] protectDiscSignature = {0x48, 0xFA, 0x4D, 0x45, 0x54, 0x49, 0x4E, 0x46};
        /// <summary>
        ///     "\0\0BoG_"
        /// </summary>
        static byte[] safeDisc3Signature    = {0x00, 0x00, 0x42, 0x6F, 0x47, 0x5F};
        const string PROTECT_DISC_SIGNATURE2 = "ACE-PCD";
        const string VOB_PROTECT_SIGNATURE = "DCP-VOB";
        static byte[] activeMark5Signature  =
            {32, 194, 22, 0, 168, 193, 22, 0, 184, 193, 22, 0, 134, 200, 22, 0, 154, 193, 22, 0, 16, 194, 22, 0};
        const string ACTIVE_MARK_SIGNATURE = "TMSAMVOF";
        const string ALPHA_ROM_SIGNATURE = "SETTEC";
        static byte[] armadilloSignature           = {0x2E, 0x6E, 0x69, 0x63, 0x6F, 0x64, 0x65, 0x00};
        const string ARMADILLO_SIGNATURE2 = "ARMDEBUG";
        const string THREE_P_LOCK_SIGNATURE = ".ldr";
        const string THREE_P_LOCK_SIGNATURE2 = ".ldt";
        const string CD_SHIELD_SE_SIGNATURE = "~0017.tmp";
        const string CENEGA_SIGNATURE = ".cenega";
        const string CODE_LOCK_SIGNATURE2 = "CODE-LOCK.OCX";
        const string COPY_KILLER_SIGNATURE = "Tom Commander";
        const string GAMES_FOR_WINDOWS_LIVE_SIGNATURE = "xlive.dll";
        const string IMPULSE_REACTOR_SIGNATURE = "CVPInitializeClient";
        const string JO_WOOD2_SIGNATURE = "@HC09    ";
        const string KEY_LOCK_SIGNATURE = "KEY-LOCK COMMAND";
        const string SAFE_LOCK_SIGNATURE = "SafeLock";
        static byte[] cdCopsSignature2             = {0x2E, 0x67, 0x72, 0x61, 0x6E, 0x64, 0x00};
        static byte[] cdLockSignature              =
        {
            0x32, 0xF2, 0x2, 0x82, 0xC3, 0xBC, 0xB, 0x24, 0x99, 0xAD, 0x27, 0x43, 0xE4, 0x9D, 0x73, 0x74, 0x99, 0xFA, 0x32, 0x24, 0x9D, 0x29,
            0x34, 0xFF, 0x74
        };
        static byte[] exeStealthSignature =
        {
            0x3F, 0x3F, 0x5B, 0x5B, 0x5F, 0x5F, 0x5B, 0x5B, 0x5F, 0x0, 0x7B, 0x7B, 0x0, 0x0, 0x7B, 0x7B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3F, 0x3B, 0x3B, 0x3F,
            0x3F, 0x3B, 0x3B, 0x3F, 0x3F
        };
        static byte[] impulseReactorSignature2 =
        {
            0x41, 0x00, 0x54, 0x00, 0x54, 0x00, 0x4C, 0x00, 0x49, 0x00, 0x53, 0x00, 0x54, 0x00, 0x00, 0x00, 0x45, 0x00,
            0x4C, 0x00, 0x45, 0x00, 0x4D, 0x00, 0x45, 0x00, 0x4E, 0x00, 0x54, 0x00, 0x00, 0x00, 0x4E, 0x00, 0x4F, 0x00,
            0x54, 0x00, 0x41, 0x00, 0x54, 0x00, 0x49, 0x00, 0x4F, 0x00, 0x4E
        };
        static byte[] ringProtechSignature =
            {0x00, 0x41, 0x6C, 0x6C, 0x6F, 0x63, 0x61, 0x74, 0x6F, 0x72, 0x00, 0x00, 0x00, 0x00};
        const string SMARTE_SIGNATURE = "BITARTS";
        static byte[] solidShield1Signature     = {0xEF, 0xBE, 0xAD, 0xDE};
        static byte[] solidShieldTagesSignature =
        {
            0x54, 0x0, 0x61, 0x0, 0x67, 0x0, 0x65, 0x0, 0x73, 0x0, 0x53, 0x0, 0x65, 0x0, 0x74, 0x0, 0x75, 0x0, 0x70, 0x0, 0x0, 0x0, 0x0, 0x0, 0x30, 0x0,
            0x8, 0x0, 0x1, 0x0, 0x46, 0x0, 0x69, 0x0, 0x6c, 0x0, 0x65, 0x0, 0x56, 0x0, 0x65, 0x0, 0x72, 0x0, 0x73, 0x0, 0x69, 0x0, 0x6F, 0x0, 0x6E,
            0x00, 0x00, 0x00, 0x00
        };
        static byte[] svkSignature             = {0x3F, 0x53, 0x56, 0x4B, 0x50, 0x00, 0x00};
        const string TAGES_SIGNATURE = "tagesprotection.com";
        const string VOB_PROTECT_CD_SIGNATURE2 = ".vob.pcd";
        const string WTM_PROTECT_SIGNATURE = "WTM76545";
        const string XTREME_PROTECTOR_SIGNATURE = "XPROT   ";
        static byte[] tagesSignature2          = {232, 117, 0, 0, 0, 232};
        const string GET_DRIVE_TYPE = "GetDriveType";
        const string GET_VOLUME_INFORMATION = "GetVolumeInformation";

        public static string Scan(string path, bool advancedscan, bool sizelimit = true)
        {
            string version = "";
            int    i;

            isImpulseReactorWithoutVersion = false;
            isLaserLockWithoutVersion      = false;
            isSafeDiscRemovedVersion       = false;
            isSolidShieldWithoutVersion    = false;
            isStarForceWithoutVersion      = false;
            secuRoMpaulversion             = "";

            string[]   filesstr                           = GetAllFiles(path);
            FileInfo[] files                              = new FileInfo[filesstr.Length];
            for(i = 0; i < filesstr.Length; i++) files[i] = new FileInfo(filesstr[i]);

            string[] exeFiles = GetAllFiles(path, "*.icd|*.dat|*.exe|*.dll");

            if(exeFiles.Length != 0)
                for(i = 0; i   < exeFiles.Length; i++)
                {
                    FileInfo filei = new FileInfo(exeFiles[i]);
                    if(filei.Length <= 352 || sizelimit && filei.Length > Filesizelimit) continue;

                    Console.WriteLine("scanning file Nr. {0} ({1})", i, exeFiles[i]);
                    string protectionname = ScaninFile(exeFiles[i], advancedscan);
                    if(!string.IsNullOrEmpty(protectionname))
                    {
                        if(isImpulseReactorWithoutVersion)
                        {
                            isImpulseReactorWithoutVersion = false;
                            if(ImpulseReactor(ref version, files)) return $"Impulse Reactor {version}";
                        }

                        else if(isLaserLockWithoutVersion)
                        {
                            isLaserLockWithoutVersion = false;
                            if(LaserLock(ref version, path, files) && !string.IsNullOrEmpty(version))
                                return $"LaserLock {version}";
                        }
                        else if(isSafeDiscRemovedVersion)
                        {
                            isSafeDiscRemovedVersion = false;
                            if(SafeDisc2(ref version, path, files) && version != "2-4") return $"SafeDisc {version}";
                        }
                        else if(isSolidShieldWithoutVersion)
                        {
                            isSolidShieldWithoutVersion = false;
                            if(SolidShield(ref version, files) && !string.IsNullOrEmpty(version)) return version;
                        }
                        else if(isStarForceWithoutVersion)
                        {
                            isStarForceWithoutVersion = false;
                            if(StarForce(ref version, files) && !string.IsNullOrEmpty(version)) return version;
                        }

                        if(!string.IsNullOrEmpty(secuRoMpaulversion))
                        {
                            if(!protectionname.StartsWith("SecuROM Product Activation"))
                                return $"{protectionname} + SecuROM Product Activation {secuRoMpaulversion}";
                        }
                        else return protectionname;
                    }

                    GC.Collect(2); //to free memory
                }

            if(Aacs(path)) return "AACS";

            if(AlphaDvd(files)) return "Alpha-DVD";

            if(Bitpool(files)) return "Bitpool";

            if(ByteShield(path, files)) return "ByteShield";

            if(Cactus(ref version, files)) return "Cactus Data Shield {version}";

            ;
            if(CdCops(path, files)) return "CD-Cops";

            if(CdProtector(path, files)) return "CD-Protector";

            if(CdLock(path)) return "CD-Lock";

            if(Cdx(files)) return "CD-X";

            if(DiskGuard(files)) return "Diskguard";

            if(DvdCrypt(files)) return "DVD Crypt";

            if(DvdMovieProtect(path)) return "DVD-Movie-PROTECT";

            if(FreeLock(files)) return "FreeLock";

            if(HexalockAutoLock(files)) return "Hexalock AutoLock";

            if(ImpulseReactor(ref version, files)) return "Impulse Reactor {version}";

            if(IndyVcd(files)) return "IndyVCD";

            if(Key2AudioXs(files)) return "Key2Audio XS";

            if(LaserLock(ref version, path, files)) return "LaserLock {version}";

            if(MediaCloQ(files)) return "MediaCloQ";

            if(MediaMaxCd3(files)) return "MediaMax CD-3";

            if(ProtectDvdVideo(path)) return "Protect DVD-Video";

            if(Psx(path, files)) return "PSX Libcrypt";

            if(SafeCast(files)) return "SafeCast";

            if(SafeDiscLite(files)) return "SafeDisc Lite";

            if(SafeDisc2(ref version, path, files)) return "SafeDisc {version}";

            if(TzCopyProtector(files))
                return "TZCopyProtector"; //has to be checked before SafeDisc because SafeDiscsearch searches for *.016

            if(SafeDisc1(ref version, path, files)) return "SafeDisc {version}";

            if(Safe_Lock(files)) return "SafeLock";

            if(SecuRom(files)) return "SecuROM";

            if(SecuRoMnew(files)) return "SecuROM new";

            if(Smarte(files)) return "Smarte";

            if(SolidShield(ref version, files)) return version;

            if(Softlock(files)) return "Softlock";

            if(StarForce(ref version, files)) return version;

            if(Tages(files)) return "TAGES";

            if(VobProtectCddvd(files)) return "VOB ProtectCD/DVD";

            if(WinLock(files)) return "Winlock";

            if(WtmcdProtect(path)) return "WTM CD Protect";

            if(WtmCopyProtection(ref version, files)) return "WTM Copy Protection {version}";

            if(Xcp(path, files)) return "XCP";

            //if(CopyKiller(files) ) return "could be CopyKiller / SecuROM";

            if(Dummyfiles(files)) IsDummyfiles = true;

            return "";
        }

        public static string ScaninFile(string file, bool advancedscan)
        {
            byte[]       fileData;
            StreamReader sr;
            try { sr = new StreamReader(file, Encoding.Default); }
            catch(Exception) { return ""; }

            try
            {
                if(!(sr.BaseStream.ReadByte() == 77 && sr.BaseStream.ReadByte() == 90))
                {
                    sr.Close();
                    return "";
                }

                sr.BaseStream.Seek(0, SeekOrigin.Begin);
                fileData    = new byte[sr.BaseStream.Length];
                sr.BaseStream.Read(fileData, 0, fileData.Length);
            }
            catch(Exception)
            {
                sr.Close();
                return "";
            }

            sr.Close();
            int position = InArray(fileData, safeDiscSignature);
            if(position >= 0)
            {
                if(InArray(fileData, Encoding.Unicode.GetBytes(SAFE_CAST_SIGNATURE)) >= 0)
                    return "SafeCast " + GetSafeDiscVersion(file, position);

                return "SafeDisc " + GetSafeDiscVersion(file, position);
            }

            position = InArray(fileData, secuRom4Signature);
            if(position >= 0) return "SecuROM " + GetSecuRom4Version(file, position);

            position = InArray(fileData, secuRom5Signature);
            if(position >= 0) return "SecuROM " + GetSecuRom4And5Version(file, position);

            if(PrefixInArray(fileData, Encoding.ASCII.GetBytes(".securom"), new byte[] {0xE0}, new byte[] {0xC0}) >= 0)
                return "SecuROM " + GetSecuRom7Version(file);

            if(InArray(fileData, secuRomPaulSignature) >= 0)
            {
                secuRoMpaulversion = GetFileVersion(file);
                return "SecuROM Product Activation " + secuRoMpaulversion;
            }

            position = InArray(fileData, Encoding.ASCII.GetBytes(CD_COPS_SIGNATURE));
            if(position >= 0) return "CD-Cops " + GetCddvdCopsVersion(file, position);

            position = InArray(fileData, Encoding.ASCII.GetBytes(DVD_COPS_SIGNATURE));
            if(position >= 0) return "DVD-Cops " + GetCddvdCopsVersion(file, position);

            position = InArray(fileData, Encoding.ASCII.GetBytes(VOB_PROTECT_CD_SIGNATURE));
            if(position >= 0) return "VOB ProtectCD/DVD " + GetProtectCDoldVersion(file, position);

            position = InArray(fileData, Encoding.ASCII.GetBytes(SYSIPHUS_SIGNATURE));
            if(position >= 0)
            {
                if(Encoding.ASCII.GetString(fileData, position + 10, 3) == "DVD")
                    return "Sysiphus DVD "        + GetSysiphusVersion(file, position);

                return "Sysiphus " + GetSysiphusVersion(file, position);
            }

            if(InArray(fileData, Encoding.ASCII.GetBytes(STAR_FORCE_SIGNATURE))  >= 0 ||
               InArray(fileData, Encoding.ASCII.GetBytes(STAR_FORCE_SIGNATURE2)) >= 0)
            {
                isStarForceWithoutVersion = true;
                return "StarForce 3-5";
            }

            if(InArray(fileData, starForce5Signature) >= 0)
            {
                isStarForceWithoutVersion = true;
                return "StarForce 5";
            }

            if(InArray(fileData, starForceSignature3)                          >= 0 ||
               InArray(fileData, Encoding.ASCII.GetBytes(STAR_FORCE_SIGNATURE4)) >= 0)
            {
                position = InArray(fileData, Encoding.Unicode.GetBytes("TradeName"));
                if(position != -1)
                    return "StarForce "                                       + GetFileVersion(file)      + " (" +
                           Encoding.ASCII.GetString(fileData, position + 22, 30).Split('\0')[0] + ")";

                return "StarForce " + GetFileVersion(file);
            }

            if(InArray(fileData, solidShieldSignature) >= 0) return "SolidShield " + GetFileVersion(file);

            if(InArray(fileData, Encoding.ASCII.GetBytes(LASER_LOCK_MARATHON_SIGNATURE)) >= 0)
            {
                position = InArray(fileData, laserLockSignature);
                if(position == -1) return "LaserLock Marathon " + GetLaserLockBuild(fileData, true);

                return "LaserLock " + GetLaserLockVersion(fileData, position) + " " +
                       GetLaserLockBuild(fileData, true);
            }

            position = InArray(fileData, laserLockSignature);
            if(position >= 0)
                return "LaserLock " + GetLaserLockVersion(fileData, position) + " " +
                       GetLaserLockBuild(fileData, false);

            if(InArray(fileData, laserLock5Signature) >= 0)
            {
                isLaserLockWithoutVersion = true;
                return "LaserLock 5";
            }

            if(InArray(fileData, laserLock3Signature) >= 0)
            {
                isLaserLockWithoutVersion = true;
                return "LaserLock 3";
            }

            if(InArray(fileData, Encoding.ASCII.GetBytes(JO_WOOD_SIGNATURE)) >= 0)
            {
                position = InArray(fileData, joWoodSignature2);
                if(position >= 0) return "JoWooD X-Prot " + GetJoWooDxProt1Version(file, position);

                return "JoWooD X-Prot v1";
            }

            position = InArray(fileData, protectDiscSignature);
            if(position >= 0) return "ProtectDisc " + GetProtectDiscVersionBuild76Till10(file, position);

            if(InArray(fileData, safeDisc3Signature) >= 0 || SuffixInArray(fileData, Encoding.ASCII.GetBytes("stxt"), Encoding.ASCII.GetBytes("774"), Encoding.ASCII.GetBytes("371")) >= 0)
            {
                /*if (advancedscan)
                {
                    string version;
                    version = EVORE.SearchSafeDiscversion(file);
                    if (version.Length)
                        return "SafeDisc " + version;
                }*/

                isSafeDiscRemovedVersion = true;
                return "SafeDisc 3.20-4.xx (version removed)";
            }

            position = InArray(fileData, Encoding.ASCII.GetBytes(PROTECT_DISC_SIGNATURE2));
            if(position >= 0) return "ProtectDisc " + GetProtectDiscVersionBuild6Till8(file, position);

            if(InArray(fileData, Encoding.ASCII.GetBytes(VOB_PROTECT_SIGNATURE)) >= 0)
            {
                string version = GetVobProtectCddvdVersion(file, position);
                if(!string.IsNullOrEmpty(version)) return "VOB ProtectCD/DVD " + version;

                /*if (advancedscan)
                {
                    version = EVORE.SearchProtectDiscversion(file);
                    if (version.Length)
                    {
                        if (version.StartsWith("2"))
                        {
                            version = "6" + version.Substring(1);
                        }
        
                        return "VOB ProtectCD/DVD " + version;
                    }
                }*/

                return "VOB ProtectCD/DVD 5.9-6.0" + GetVobProtectCddvdBuild(file, position);
            }

            if(InArray(fileData, activeMark5Signature) >= 0) return "ActiveMARK 5";

            if(InArray(fileData, Encoding.ASCII.GetBytes(ACTIVE_MARK_SIGNATURE)) >= 0) return "ActiveMARK";

            if(InArray(fileData, Encoding.ASCII.GetBytes(ALPHA_ROM_SIGNATURE)) >= 0) return "Alpha-ROM";

            if(InArray(fileData, armadilloSignature)                           >= 0 ||
               InArray(fileData, Encoding.ASCII.GetBytes(ARMADILLO_SIGNATURE2)) >= 0) return "Armadillo";

            if(InArray(fileData, Encoding.ASCII.GetBytes(THREE_P_LOCK_SIGNATURE))  >= 0 &&
               InArray(fileData, Encoding.ASCII.GetBytes(THREE_P_LOCK_SIGNATURE2)) >= 0) return "3PLock";

            if(InArray(fileData, cdCopsSignature2) >= 0) return "CD-Cops";

            if(InArray(fileData, cdLockSignature) >= 0) return "CD-Lock";

            if(InArray(fileData, Encoding.ASCII.GetBytes(CD_SHIELD_SE_SIGNATURE)) >= 0) return "CDSHiELD SE";

            if(InArray(fileData, Encoding.ASCII.GetBytes(CENEGA_SIGNATURE)) >= 0) return "Cenega ProtectDVD";

            if(SuffixInArray(fileData, Encoding.ASCII.GetBytes("icd"), new byte[] {0x31, 0x00}, new byte[] {0x32, 0x00})    >= 0 ||
               InArray(fileData, Encoding.ASCII.GetBytes(CODE_LOCK_SIGNATURE2)) >= 0) return "Code Lock";

            if(InArray(fileData, Encoding.ASCII.GetBytes(COPY_KILLER_SIGNATURE)) >= 0) return "CopyKiller";

            if(InArray(fileData, exeStealthSignature) >= 0) return "EXE Stealth";

            if(InArray(fileData, Encoding.ASCII.GetBytes(GAMES_FOR_WINDOWS_LIVE_SIGNATURE)) >= 0)
                return "Games for Windows - Live";

            if(InArray(fileData,     Encoding.ASCII.GetBytes(IMPULSE_REACTOR_SIGNATURE)) >= 0)
                if(InArray(fileData, impulseReactorSignature2)                         >= 0)
                    return "Impulse Reactor " + GetFileVersion(file);
                else
                {
                    isImpulseReactorWithoutVersion = true;
                    return "Impulse Reactor";
                }

            if(InArray(fileData, Encoding.ASCII.GetBytes(JO_WOOD2_SIGNATURE)) >= 0) return "JoWooD X-Prot v2";

            if(InArray(fileData, Encoding.ASCII.GetBytes(KEY_LOCK_SIGNATURE)) >= 0) return "Key-Lock (Dongle)";

            if(InArray(fileData, ringProtechSignature) >= 0) return "Ring-Protech";

            if(InArray(fileData, Encoding.ASCII.GetBytes(SAFE_LOCK_SIGNATURE)) >= 0) return "SafeLock";

            if(SuffixInArray(fileData, Encoding.ASCII.GetBytes(".cms_"), new byte[]{0x74, 0x00}, new byte[]{0x64, 0x00 }) >= 0) return "SecuROM 1-3";

            if(InArray(fileData, Encoding.ASCII.GetBytes(SMARTE_SIGNATURE)) >= 0) return "Smarte";

            position = InArray(fileData, solidShield1Signature);
            if(position >= 0)
            {
                byte[] piece1 = new byte[3];
                byte[] piece2 = new byte[4];
                
                Array.Copy(fileData, position + 5,  piece1, 0, 3);
                Array.Copy(fileData, position + 16, piece2, 0, 4);
                if(piece1.SequenceEqual(new byte[] {0, 0, 0}) &&
                   piece2.SequenceEqual(new byte[] {0, 16, 0, 0}))
                {
                    isSolidShieldWithoutVersion = true;
                    return "SolidShield 1";
                }
            }

            position = SuffixInArray(fileData,
                                   new byte[] {0xAD, 0xDE, 0xFE, 0xCA},
                                   new byte[] {0x05}, new byte[] {0x04});
            if(position >= 0)
            {
                byte[] piece1 = new byte[3];
                byte[] piece2 = new byte[4];
                
                Array.Copy(fileData, position + 5, piece1, 0, 3);
                Array.Copy(fileData, position + 16, piece2, 0, 4);
                
                if(piece1.SequenceEqual(new byte[] {0, 0, 0}) &&
                   piece2.SequenceEqual(new byte[] {0, 16, 0, 0}))
                    return "SolidShield 2";

                if(piece1.SequenceEqual(new byte[] {0, 0, 0}) &&
                   piece2.SequenceEqual(new byte[] {0, 0, 0, 0}))
                {
                    position = InArray(fileData, solidShieldTagesSignature);
                    if(position >= 0)
                        return "SolidShield 2 + Tagès "       + Encoding.ASCII.GetString(fileData, position + 56, 1) + "." +
                               Encoding.ASCII.GetString(fileData, position + 56                             + 4,  1) + "." +
                               Encoding.ASCII.GetString(fileData, position + 56                             + 8,  1) + "." +
                               Encoding.ASCII.GetString(fileData, position + 56                             + 12, 1);

                    isSolidShieldWithoutVersion = true;
                    return "SolidShield 2";
                }
            }

            if(InArray(fileData, svkSignature) >= 0) return "SVK Protector";

            if(InArray(fileData, Encoding.ASCII.GetBytes(TAGES_SIGNATURE)) >= 0) return "Tagès " + GetFileVersion(file);

            position = InArray(fileData, tagesSignature2);
            if(position >= 0)
            {
                byte[] piece = new byte[3];
                Array.Copy(fileData, position + 8, piece, 0, 3);
                if(piece.SequenceEqual(new byte[] {255, 255, 104}))
                    return "Tagès "               + GetTagesVersion(file, position);
            }

            if(InArray(fileData, Encoding.ASCII.GetBytes(VOB_PROTECT_CD_SIGNATURE2)) >= 0) return "VOB ProtectCD";

            if(InArray(fileData, Encoding.ASCII.GetBytes(WTM_PROTECT_SIGNATURE)) >= 0) return "WTM CD Protect";

            if(InArray(fileData, Encoding.ASCII.GetBytes(XTREME_PROTECTOR_SIGNATURE)) >= 0) return "Xtreme-Protector";

            if(IsCdCheck) return "";

            if(InArray(fileData, Encoding.ASCII.GetBytes(GET_DRIVE_TYPE))         >= 0 ||
               InArray(fileData, Encoding.ASCII.GetBytes(GET_VOLUME_INFORMATION)) >= 0) IsCdCheck = true;

            return "";
        }

        #region Protections
        static bool Aacs(string path)
        {
            return File.Exists(path + "aacs\\VTKF000.AACS") || File.Exists(path + "\\AACS\\CPSUnit00001.cci");
        }

        static bool AlphaDvd(FileInfo[] files)
        {
            return FileExists("PlayDVD.exe", files) >= 0;
        }

        static bool Bitpool(FileInfo[] files)
        {
            return FileExists("bitpool.rsc", files) >= 0;
        }

        static bool ByteShield(string path, FileInfo[] files)
        {
            if(FileExists("Byteshield.dll", files) >= 0) return true;

            return GetAllFiles(path, "*.bbz").Length > 0;
        }

        static bool Cactus(ref string version, FileInfo[] files)
        {
            bool found = FileExists("yucca.cds",     files) >= 0 || FileExists("wmmp.exe",     files) >= 0 ||
                         FileExists("PJSTREAM.DLL",  files) >= 0 || FileExists("CACTUSPJ.exe", files) >= 0 ||
                         FileExists("CDSPlayer.app", files) >= 0;
            if(!found) return false;

            int fileindex = FileExists("Version.txt", files);
            if(fileindex >= 0)
            {
                StreamReader sr = new StreamReader(files[fileindex].FullName);
                version         = sr.ReadLine()?.Substring(3) + " (" + sr.ReadLine() + ")";
            }
            else version = "200";

            return true;
        }

        static bool CdCops(string path, FileInfo[] files)
        {
            if(FileExists("CDCOPS.DLL", files)   >= 0) return true;
            if(GetAllFiles(path, "*.GZ_").Length > 0) return true;
            if(GetAllFiles(path, "*.W_X").Length > 0) return true;
            if(GetAllFiles(path, "*.Qz").Length  > 0) return true;

            return GetAllFiles(path, "*.QZ_").Length > 0;
        }

        static bool CdLock(string path)
        {
            return GetAllFiles(path, "*.AFP").Length > 0;
        }

        static bool CdProtector(string path, FileInfo[] files)
        {
            if(FileExists("_cdp16.dat", files) >= 0) return true;
            if(FileExists("_cdp16.dll", files) >= 0) return true;
            if(FileExists("_cdp32.dat", files) >= 0) return true;

            return FileExists("_cdp32.dll", files) >= 0;
        }

        static bool Cdx(FileInfo[] files)
        {
            if(FileExists("CHKCDX16.DLL", files) >= 0) return true;
            if(FileExists("CHKCDX32.DLL", files) >= 0) return true;

            return FileExists("CHKCDXNT.DLL", files) >= 0;
        }

        static bool DiskGuard(FileInfo[] files)
        {
            if(FileExists("IOSLINK.VXD", files) >= 0) return true;
            if(FileExists("IOSLINK.DLL", files) >= 0) return true;

            return FileExists("IOSLINK.SYS", files) >= 0;
        }

        static bool DvdCrypt(FileInfo[] files)
        {
            return FileExists("DvdCrypt.pdb", files) >= 0;
        }

        static bool DvdMovieProtect(string path)
        {
            if(!Directory.Exists(path + "VIDEO_TS")) return false;

            string[] bupfiles = GetAllFiles(path, "*.bup");
            int      i;
            for(i = 0; i <= bupfiles.Length - 1; i++)
            {
                FileInfo bupfile = new FileInfo(bupfiles[i]);
                FileInfo ifofile = new FileInfo(bupfile.DirectoryName + "\\" +
                                                bupfile
                                                   .Name.Substring(0, bupfile.Name.Length - bupfile.Extension.Length) +
                                                ".ifo");
                if(bupfile.Length != ifofile.Length) return true;
            }

            return false;
        }

        static bool FreeLock(FileInfo[] files)
        {
            return FileExists("FREELOCK.IMG", files) >= 0;
        }

        static bool HexalockAutoLock(FileInfo[] files)
        {
            if(FileExists("Start_Here.exe", files) >= 0) return true;
            if(FileExists("HCPSMng.exe",    files) >= 0) return true;
            if(FileExists("MFINT.DLL",      files) >= 0) return true;

            return FileExists("MFIMP.DLL", files) >= 0;
        }

        static bool ImpulseReactor(ref string version, FileInfo[] files)
        {
            int i = FileExists("ImpulseReactor.dll", files);
            if(i < 0) return false;

            version = GetFileVersion(files[i].FullName);
            return true;
        }

        static bool IndyVcd(FileInfo[] files)
        {
            if(FileExists("INDYVCD.AX", files) >= 0) return true;

            return FileExists("INDYMP3.idt", files) >= 0;
        }

        static bool Key2AudioXs(FileInfo[] files)
        {
            if(FileExists("SDKHM.EXE", files) >= 0) return true;

            return FileExists("SDKHM.DLL", files) >= 0;
        }

        static bool LaserLock(ref string version, string path, FileInfo[] files)
        {
            int nomouseindex = FileExists("NOMOUSE.SP", files);
            if(nomouseindex >= 0)
            {
                version = GetLaserLockVersion16Bit(files[nomouseindex].FullName);
                return true;
            }

            if(FileExists("NOMOUSE.COM",  files) >= 0) return true;
            if(FileExists("l16dll.dll",   files) >= 0) return true;
            if(FileExists("laserlok.in",  files) >= 0) return true;
            if(FileExists("laserlok.o10", files) >= 0) return true;

            return FileExists("laserlok.011", files) >= 0 || Directory.Exists(path + "LASERLOK");
        }

        static bool MediaCloQ(FileInfo[] files)
        {
            return FileExists("sunncomm.ico", files) >= 0;
        }

        static bool MediaMaxCd3(FileInfo[] files)
        {
            return FileExists("LaunchCd.exe", files) >= 0;
        }

        static bool ProtectDvdVideo(string path)
        {
            if(!Directory.Exists(path + "VIDEO_TS")) return false;

            string[] ifofiles = GetAllFiles(path, "*.ifo");
            int      i;
            for(i = 0; i <= ifofiles.Length - 1; i++)
            {
                FileInfo ifofile = new FileInfo(ifofiles[i]);
                if(ifofile.Length == 0) return true;
            }

            return false;
        }

        static bool Psx(string path, FileInfo[] files)
        {
            if(FileExists("SLES_016.83", files) >= 0) return true;

            return GetAllFiles(path, "*.cnf").Length > 0;
        }

        static bool SafeCast(FileInfo[] files)
        {
            return FileExists("cdac11ba.exe", files) >= 0;
        }

        static bool SafeDisc1(ref string version, string path, FileInfo[] files)
        {
            bool found = FileExists("00000001.TMP",    files) >= 0 || FileExists("CLCD16.DLL",  files) >= 0 ||
                         FileExists("CLCD32.DLL",      files) >= 0 || FileExists("CLOKSPL.EXE", files) >= 0;
            int fileindex = FileExists("DPLAYERX.DLL", files);
            if(fileindex >= 0)
            {
                found = true;
                switch(files[fileindex].Length)
                {
                    case 81408:
                        version = "1.0x";
                        break;
                    case 155648:
                        version = "1.1x";
                        break;
                    case 156160:
                        version = "1.1x-1.2x";
                        break;
                    case 163328:
                        version = "1.3x";
                        break;
                    case 165888:
                        version = "1.35";
                        break;
                    case 172544:
                        version = "1.40";
                        break;
                    case 173568:
                        version = "1.4x";
                        break;
                    case 136704:
                        version = "1.4x";
                        break;
                    case 138752:
                        version = "1.5x";
                        break;
                }
            }

            fileindex = FileExists("DrvMgt.dll", files);
            if(fileindex >= 0)
            {
                found = true;
                if(string.IsNullOrEmpty(version))
                    switch(files[fileindex].Length)
                    {
                        case 34816:
                            version = "1.0x";
                            break;
                        case 32256:
                            version = "1.1x-1.3x";
                            break;
                        case 31744:
                            version = "1.4x";
                            break;
                        case 34304:
                            version = "1.5x";
                            break;
                    }
            }

            if(GetAllFiles(path, "*.ICD").Length > 0) found = true;
            if(GetAllFiles(path, "*.016").Length > 0) found = true;
            if(GetAllFiles(path, "*.256").Length > 0) found = true;
            if(!found) return false;

            if(string.IsNullOrEmpty(version)) version = "1";

            return true;
        }

        static bool SafeDisc2(ref string version, string path, FileInfo[] files)
        {
            bool found           = FileExists("00000002.TMP", files) >= 0;
            int  fileindexdrvmgt = FileExists("DrvMgt.dll",   files);
            int  fileindexsecdrv = FileExists("secdrv.sys",   files);
            if(fileindexsecdrv                   >= 0)
                if(files[fileindexsecdrv].Length == 18768)
                {
                    found   = true;
                    version = "2.50";
                }

            if((fileindexsecdrv >= 0) & (fileindexdrvmgt >= 0))
            {
                if((files[fileindexdrvmgt].Length == 34304) & (files[fileindexsecdrv].Length == 20128))
                    version = "2.10";
                if((files[fileindexdrvmgt].Length == 34304) & (files[fileindexsecdrv].Length == 27440))
                    version = "2.30";
                if((files[fileindexdrvmgt].Length == 34304) & (files[fileindexsecdrv].Length == 28624))
                    version = "2.40";
                if((files[fileindexdrvmgt].Length == 35840) & (files[fileindexsecdrv].Length == 28400))
                    version = "2.51";
                if((files[fileindexdrvmgt].Length == 35840) & (files[fileindexsecdrv].Length == 29392))
                    version = "2.60";
                if((files[fileindexdrvmgt].Length == 40960) & (files[fileindexsecdrv].Length == 11376))
                    version = "2.70";
                if((files[fileindexdrvmgt].Length == 23552) & (files[fileindexsecdrv].Length == 12464))
                    version = "2.80";
                if((files[fileindexdrvmgt].Length == 41472) & (files[fileindexsecdrv].Length == 12400))
                    version = "2.90";
                if((files[fileindexdrvmgt].Length == 41472) & (files[fileindexsecdrv].Length == 12528))
                    version = "3.10";
                if((files[fileindexdrvmgt].Length == 24064) & (files[fileindexsecdrv].Length == 12528))
                    version = "3.15";
                if((files[fileindexdrvmgt].Length == 24064) & (files[fileindexsecdrv].Length == 11973))
                    version             = "3.20";
                if(version != "") found = true;
            }

            if((fileindexdrvmgt >= 0) & (version == ""))
            {
                switch(files[fileindexdrvmgt].Length)
                {
                    case 34304:
                        version = "2.0x";
                        break;
                    case 35840:
                        version = "2.6x";
                        break;
                    case 40960:
                        version = "2.7x";
                        break;
                    case 23552:
                        version = "2.8x";
                        break;
                    case 41472:
                        version = "2.9x";
                        break;
                }

                if(version != "") found = true;
            }

            if(!found) return false;

            if(version == "") version = "2-4";

            return true;
        }

        static bool SafeDiscLite(FileInfo[] files)
        {
            return FileExists("00000001.LT1", files) >= 0;
        }

        static bool Safe_Lock(FileInfo[] files)
        {
            if(FileExists("SafeLock.dat", files) >= 0) return true;
            if(FileExists("SafeLock.001", files) >= 0) return true;

            return FileExists("SafeLock.128", files) >= 0;
        }

        static bool SecuRom(FileInfo[] files)
        {
            if(FileExists("CMS16.DLL",    files) >= 0) return true;
            if(FileExists("CMS_95.DLL",   files) >= 0) return true;
            if(FileExists("CMS_NT.DLL",   files) >= 0) return true;
            if(FileExists("CMS32_95.DLL", files) >= 0) return true;

            return FileExists("CMS32_NT.DLL", files) >= 0;
        }

        static bool SecuRoMnew(FileInfo[] files)
        {
            if(FileExists("SINTF32.DLL", files) >= 0) return true;
            if(FileExists("SINTF16.DLL", files) >= 0) return true;

            return FileExists("SINTFNT.DLL", files) >= 0;
        }

        static bool Smarte(FileInfo[] files)
        {
            if(FileExists("00001.TMP", files) >= 0) return true;

            return FileExists("00002.TMP", files) >= 0;
        }

        static bool SolidShield(ref string versionName, FileInfo[] files)
        {
            int fileindex = FileExists("dvm.dll", files);
            if(fileindex >= 0)
            {
                versionName = ScaninFile(files[fileindex].FullName, false);
                return true;
            }

            fileindex = FileExists("hc.dll", files);
            if(fileindex >= 0)
            {
                versionName = ScaninFile(files[fileindex].FullName, false);
                return true;
            }

            fileindex = FileExists("solidshield-cd.dll", files);
            if(fileindex >= 0)
            {
                versionName = ScaninFile(files[fileindex].FullName, false);
                return true;
            }

            fileindex = FileExists("c11prot.dll", files);
            if(fileindex < 0) return false;

            versionName = ScaninFile(files[fileindex].FullName, false);
            return true;
        }

        static bool Softlock(FileInfo[] files)
        {
            if(FileExists("SOFTLOCKI.dat", files) >= 0) return true;

            return FileExists("SOFTLOCKC.dat", files) >= 0;
        }

        static bool StarForce(ref string starforceversion, FileInfo[] files)
        {
            int fileindex = FileExists("protect.dll", files);
            if(fileindex >= 0)
            {
                starforceversion = ScaninFile(files[fileindex].FullName, false);
                return true;
            }

            fileindex = FileExists("protect.exe", files);
            if(fileindex < 0) return false;

            starforceversion = ScaninFile(files[fileindex].FullName, false);
            return true;
        }

        static bool Tages(FileInfo[] files)
        {
            if(FileExists("Tages.dll",          files) >= 0) return true;
            if(FileExists("tagesclient.exe",    files) >= 0) return true;
            if(FileExists("TagesSetup.exe",     files) >= 0) return true;
            if(FileExists("TagesSetup_x64.exe", files) >= 0) return true;

            return FileExists("Wave.aif", files) >= 0;
        }

        static bool TzCopyProtector(FileInfo[] files)
        {
            return FileExists("_742893.016", files) >= 0;
        }

        static bool VobProtectCddvd(FileInfo[] files)
        {
            return FileExists("VOB-PCD.KEY", files) >= 0;
        }

        static bool WinLock(FileInfo[] files)
        {
            return FileExists("WinLock.PSX", files) >= 0;
        }

        static bool WtmcdProtect(string path)
        {
            return GetAllFiles(path, "*.IMP").Length > 0;
        }

        static bool WtmCopyProtection(ref string version, FileInfo[] files)
        {
            if(!((FileExists("imp.dat", files) >= 0) | (FileExists("wtmfiles.dat", files) >= 0))) return false;

            if(FileExists("Viewer.exe",                                 files) >= 0)
                version = GetFileVersion(files[FileExists("Viewer.exe", files)].FullName);

            return true;
        }

        static bool Xcp(string path, FileInfo[] files)
        {
            if(FileExists("XCP.DAT", files) >= 0) return true;

            return FileExists("ECDPlayerControl.ocx", files) >= 0 || File.Exists(path + "contents\\go.exe");
        }

        static bool Dummyfiles(IList<FileInfo> files)
        {
            int i;
            for(i = 0; i <= files.Count - 1; i++)
                try
                {
                    if(files[i].Length > 681574400) return true;
                }
                catch(Exception)
                {
                    // ignored
                }

            return false;
        }

        static string GetCddvdCopsVersion(string file, int position)
        {
            byte[]       version = new byte[4];
            BinaryReader br = new BinaryReader(new StreamReader(file).BaseStream);
            br.BaseStream.Seek(position + 15, SeekOrigin.Begin);
            version = br.ReadBytes(4);
            return version[0] == 0 ? "" : Encoding.ASCII.GetString(version);
        }

        static string GetJoWooDxProt1Version(string file, int position)
        {
            BinaryReader br = new BinaryReader(new StreamReader(file).BaseStream);
            br.BaseStream.Seek(position + 67, SeekOrigin.Begin);
            int version = br.ReadByte() - 0x30;
            br.ReadByte();
            int subVersion = br.ReadByte() - 0x30;
            br.ReadByte();
            int subsubVersion = br.ReadByte() - 0x30;
            br.ReadByte();
            int subsubsubVersion1 = br.ReadByte() - 0x30;
            int subsubsubVersion2 = br.ReadByte() - 0x30;
            br.Close();
            return $"{version}.{subVersion}.{subsubVersion}.{subsubsubVersion1}{subsubsubVersion2}";
        }

        static string GetLaserLockBuild(byte[] fileData, bool version2)
        {
            byte[] signature = {0x55, 0x6E, 0x6B, 0x6F, 0x77, 0x6E, 0x00, 0x55, 0x6E, 0x6B, 0x6F, 0x77, 0x6E};

            int    position = InArray(fileData, signature);
            string year;
            string month;
            string day;
            if(version2)
            {
                day   = Encoding.ASCII.GetString(fileData, position + 14,     2);
                month = Encoding.ASCII.GetString(fileData, position + 14 + 3, 2);
                year  = "20"                                        +
                        Encoding.ASCII.GetString(fileData, position + 14 + 6, 2);
            }
            else
            {
                day   = Encoding.ASCII.GetString(fileData, position + 13,     2);
                month = Encoding.ASCII.GetString(fileData, position + 13 + 3, 2);
                year  = "20"                                        +
                        Encoding.ASCII.GetString(fileData, position + 13 + 6, 2);
            }

            return "(Build " + year + "-" + month + "-" + day + ")";
        }

        static string GetLaserLockVersion(byte[] fileContent, int position)
        {
            return Encoding.ASCII.GetString(fileContent, position + 76, 4);
        }

        static string GetLaserLockVersion16Bit(string file)
        {
            BinaryReader br = new BinaryReader(new StreamReader(file).BaseStream);
            br.BaseStream.Seek(71, SeekOrigin.Begin);
            byte version = br.ReadByte();
            br.ReadByte();
            byte subVersion1 = br.ReadByte();
            byte subVersion2 = br.ReadByte();
            br.Close();
            if(IsNumeric(version) & IsNumeric(subVersion1) & IsNumeric(subVersion2))
                return $"{version - 0x30}.{subVersion1 - 0x30}{subVersion2 - 0x30}";

            return "";
        }

        static string GetProtectCDoldVersion(string file, int position)
        {
            BinaryReader br = new BinaryReader(new StreamReader(file).BaseStream);
            br.BaseStream.Seek(position + 16, SeekOrigin.Begin);
            byte version = br.ReadByte();
            br.ReadByte();
            byte subVersion1 = br.ReadByte();
            byte subVersion2 = br.ReadByte();
            br.Close();
            if(!(IsNumeric(version) & IsNumeric(subVersion1) & IsNumeric(subVersion2))) return "old";

            return $"{version - 0x30}.{subVersion1 - 0x30}{subVersion2 - 0x30}";
        }

        static string GetProtectDiscVersionBuild6Till8(string file, int position)
        {
            string version;
            //string Year;
            //string Month;
            //string Day;
            BinaryReader br = new BinaryReader(new StreamReader(file).BaseStream);

            br.BaseStream.Seek(position - 12, SeekOrigin.Begin);
            if(br.ReadByte() == 0xA && br.ReadByte() == 0xD && br.ReadByte() == 0xA && br.ReadByte() == 0xD
            ) //ProtectDisc 6-7 with Build Number in plain text
            {
                br.BaseStream.Seek(position - 12 - 6, SeekOrigin.Begin);
                if(Encoding.ASCII.GetString(br.ReadBytes(6)) == "Henrik") //ProtectDisc 7
                {
                    version = "7.1-7.5";
                    br.BaseStream.Seek(position - 12 - 6 - 6, SeekOrigin.Begin);
                    //br.BaseStream.Seek(position - 12 - 6 - 7, SeekOrigin.Begin);
                }
                else //ProtectDisc 6
                {
                    version = "6";
                    br.BaseStream.Seek(position - 12 - 10, SeekOrigin.Begin);
                    while(true) //search for e.g. "Build 050913 -  September 2005"
                    {
                        if(IsNumeric(br.ReadByte())) break;

                        br.BaseStream.Seek(-2, SeekOrigin.Current); //search upwards
                    }

                    br.BaseStream.Seek(-5, SeekOrigin.Current);
                }
            }
            else
            {
                br.BaseStream.Seek(position + 28, SeekOrigin.Begin);
                if(br.ReadByte() == 0xFB)
                {
                    br.Close();
                    return "7.6-7.x";
                }

                br.Close();
                return "8.0";
            }

            //Year = "20" + br.ReadChar() + br.ReadChar();
            //Month = br.ReadChar() + br.ReadChar();
            //Day = br.ReadChar() + br.ReadChar();
            //br.Close();
            //return Version + " (Build " + Year + "-" + Month + "-" + Day + ")";
            string strBuild =
                Encoding.ASCII.GetString(new[] {br.ReadByte(), br.ReadByte(), br.ReadByte(), br.ReadByte(), br.ReadByte()});
            br.Close();
            return version + " (Build " + strBuild + ")";
        }

        static string GetProtectDiscVersionBuild76Till10(string file, int position, int irefBuild = 0)
        {
            BinaryReader br = new BinaryReader(new StreamReader(file).BaseStream);
            br.BaseStream.Seek(position + 37, SeekOrigin.Begin);
            byte subversion = br.ReadByte();
            br.ReadByte();
            byte version = br.ReadByte();
            br.BaseStream.Seek(position + 49, SeekOrigin.Begin);
            irefBuild = br.ReadInt32();
            br.BaseStream.Seek(position + 53, SeekOrigin.Begin);
            byte versionindicatorPd9 = br.ReadByte();
            br.BaseStream.Seek(position + 0x40, SeekOrigin.Begin);
            byte subsubversionPd9X = br.ReadByte();
            byte subversionPd9X2   = br.ReadByte();
            byte subversionPd9X1   = br.ReadByte();
            br.Close();

            if(version == 0xAC) // version 7
                return "7." + (subversion ^ 0x43) + " (Build " + irefBuild + ")";

            if(version == 0xA2) //version 8
            {
                if(subversion           != 0x46) return "8."    + (subversion ^ 0x47) + " (Build " + irefBuild + ")";
                if((irefBuild & 0x3A00) == 0x3A00) return "8.2" + " (Build "          + irefBuild  + ")";

                return "8.1" + " (Build " + irefBuild + ")";
            }

            if(version != 0xA3) return "";

            if((subversionPd9X2 != 0x5F || subversionPd9X1 != 0x61) &&
               (subversionPd9X1 != 0    || subversionPd9X2 != 0)) return "";

            if(versionindicatorPd9 == 0xB) return "9.0-9.4" + " (Build " + irefBuild + ")";

            if(versionindicatorPd9 == 0xC)
                if(subversionPd9X2 == 0x5F && subversionPd9X1 == 0x61)
                    return "9.5-9.11" + " (Build " + irefBuild + ")";
                else if(subversionPd9X1 == 0 && subversionPd9X2 == 0)
                    return "9.11-9.20" + " (Build " + irefBuild + ")";
                else
                    return "9." + subversionPd9X1 + subversionPd9X2 + "." + subsubversionPd9X + " (Build " + irefBuild +
                           ")";

            if(version         != 0xA0) return "7.6-10.x (Build " + irefBuild + ")";
            if(subversionPd9X1 != 0 || subversionPd9X2 != 0) //version removed
                return "10." + subversionPd9X1 + "." + subsubversionPd9X + " (Build " + irefBuild + ")";

            return "10.x (Build " + irefBuild + ")";
        }

        static string GetSafeDiscVersion(string file, int position)
        {
            BinaryReader br = new BinaryReader(new StreamReader(file).BaseStream);
            br.BaseStream.Seek(position + 20, SeekOrigin.Begin);
            int version       = br.ReadInt32();
            int subVersion    = br.ReadInt32();
            int subsubVersion = br.ReadInt32();
            if(version != 0) return version + "." + subVersion.ToString("00") + "." + subsubVersion.ToString("000");

            br.BaseStream.Seek(position + 18 + 14, SeekOrigin.Begin);
            version       = br.ReadInt32();
            subVersion    = br.ReadInt32();
            subsubVersion = br.ReadInt32();
            br.Close();
            if(version == 0) return "";

            return version + "." + subVersion.ToString("00") + "." + subsubVersion.ToString("000");
        }

        static string GetSecuRom4Version(string file, int position)
        {
            BinaryReader br = new BinaryReader(new StreamReader(file).BaseStream, Encoding.Default);
            br.BaseStream.Seek(position + 8, SeekOrigin.Begin);
            int version = br.ReadByte() - 0x30;
            br.ReadByte();
            int subVersion1 = br.ReadByte() - 0x30;
            int subVersion2 = br.ReadByte() - 0x30;
            br.ReadByte();
            int subsubVersion1 = br.ReadByte() - 0x30;
            int subsubVersion2 = br.ReadByte() - 0x30;
            br.ReadByte();
            int subsubsubVersion1 = br.ReadByte() - 0x30;
            int subsubsubVersion2 = br.ReadByte() - 0x30;
            int subsubsubVersion3 = br.ReadByte() - 0x30;
            int subsubsubVersion4 = br.ReadByte() - 0x30;
            br.Close();
            return $"{version}.{subVersion1}{subVersion2}.{subsubVersion1}{subsubVersion2}.{subsubsubVersion1}{subsubsubVersion2}{subsubsubVersion3}{subsubsubVersion4}";
        }

        static string GetSecuRom4And5Version(string file, int position)
        {
            BinaryReader br = new BinaryReader(new StreamReader(file).BaseStream);
            br.BaseStream.Seek(position + 8, SeekOrigin.Begin); //Begin reading after "ÊÝÝ¬"
            byte version = (byte)(br.ReadByte() & 0xF);
            br.ReadByte();
            byte subVersion1 = (byte)(br.ReadByte() ^ 36);
            byte subVersion2 = (byte)(br.ReadByte() ^ 28);
            br.ReadByte();
            byte subsubVersion1 = (byte)(br.ReadByte() ^ 42);
            byte subsubVersion2 = (byte)(br.ReadByte() ^ 8);
            br.ReadByte();
            byte subsubsubVersion1 = (byte)(br.ReadByte() ^ 16);
            byte subsubsubVersion2 = (byte)(br.ReadByte() ^ 116);
            byte subsubsubVersion3 = (byte)(br.ReadByte() ^ 34);
            byte subsubsubVersion4 = (byte)(br.ReadByte() ^ 22);
            br.Close();
            if(version == 0 || version > 9) return "";

            return version           + "."               + subVersion1 + subVersion2 + "." + subsubVersion1 +
                   subsubVersion2    + "."               +
                   subsubsubVersion1 + subsubsubVersion2 + subsubsubVersion3 + subsubsubVersion4;
        }

        static string GetSecuRom7Version(string file)
        {
            BinaryReader br = new BinaryReader(new StreamReader(file).BaseStream);
            br.BaseStream.Seek(236, SeekOrigin.Begin);
            byte[] bytes = br.ReadBytes(4);
            //if(bytes[0] == 0xED && bytes[3] == 0x5C)
            if(bytes[3] == 0x5C) //SecuROM 7 new and 8
            {
                br.Close();
                return (bytes[0] ^ 0xEA) + "." + (bytes[1] ^ 0x2C).ToString("00") + "." +
                       (bytes[2] ^ 0x8).ToString("0000");
            }

            br.BaseStream.Seek(122, SeekOrigin.Begin);
            bytes = br.ReadBytes(2);
            br.Close();
            return "7." + (bytes[0] ^ 0x10).ToString("00") + "." + (bytes[1] ^ 0x10).ToString("0000");

            //return "7.01-7.10";
        }

        static string GetSysiphusVersion(string file, int position)
        {
            BinaryReader br = new BinaryReader(new StreamReader(file).BaseStream, Encoding.Default);
            br.BaseStream.Seek(position - 3, SeekOrigin.Begin);
            byte subVersion = br.ReadByte();
            br.ReadChar();
            byte version = br.ReadByte();
            br.Close();
            if(IsNumeric(version) & IsNumeric(subVersion)) return $"{version - 0x30}.{subVersion - 0x30}";

            return "";
        }

        static string GetTagesVersion(string file, int position)
        {
            BinaryReader br = new BinaryReader(new StreamReader(file).BaseStream);
            br.BaseStream.Seek(position + 7, SeekOrigin.Begin);
            byte bVersion = br.ReadByte();
            br.Close();
            switch(bVersion)
            {
                case 0x1B: return "5.3-5.4";
                case 0x14: return "5.5.0";
                case 0x4:  return "5.5.2";
            }

            return "";
        }

        static string GetVobProtectCddvdBuild(string file, int position)
        {
            BinaryReader br = new BinaryReader(new StreamReader(file).BaseStream);
            br.BaseStream.Seek(position - 13, SeekOrigin.Begin);
            if(!IsNumeric(br.ReadByte())) return "";

            br.BaseStream.Seek(position - 4, SeekOrigin.Begin);
            int build = br.ReadInt16();
            br.Close();
            return " (Build " + build + ")";
        }

        static string GetVobProtectCddvdVersion(string file, int position)
        {
            BinaryReader br = new BinaryReader(new StreamReader(file).BaseStream, Encoding.Default);
            br.BaseStream.Seek(position - 2, SeekOrigin.Begin);
            byte version = br.ReadByte();
            if(version != 5) return "";

            br.BaseStream.Seek(position - 4, SeekOrigin.Begin);
            byte subsubVersion = (byte)((br.ReadByte() & 0xF0) >> 4);
            byte subVersion    = (byte)((br.ReadByte() & 0xF0) >> 4);
            br.Close();
            return version + "." + subVersion + "." + subsubVersion;
        }

        static string GetFileVersion(string file)
        {
            FileVersionInfo fvinfo = FileVersionInfo.GetVersionInfo(file);
            if(fvinfo.FileVersion == null) return "";

            return fvinfo.FileVersion != ""
                       ? fvinfo.FileVersion.Replace(", ", ".")
                       : fvinfo.ProductVersion.Replace(", ", ".");
        }
        #endregion
    }
}