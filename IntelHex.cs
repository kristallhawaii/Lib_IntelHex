/*
 * SPDX-FileCopyrightText: © 2021 Matthias Keller <mkeller_service@gmx.de>
 *
 * SPDX-License-Identifier: MIT
 */
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace IntelHex
{
    enum RecordType
    {
        DataRecord = 0,
        EndofFileRecord = 1,
        SegmentAddressRecord = 2,
        LinearAddressRecord = 4
    } ;

    public enum Verbose
    {
        Quiet,
        Normal,
        Debug
    }

    class IntelHexRecord
    {
        String record_str;

        public String RecordString
        {
            get
            {
                record_str = ArrayToRecordString();
                return record_str;
            }
            set { record_str = value; ParseRecordLine(record_str); }
        }


        String bytecount_str;
        String address_str;
        String type_str;
        String data_str;
        String checksum_str;

        //public byte[] record;
        public bool checksumOK = false;
        public byte bytecount;
        private UInt16 address;
        public RecordType type;
        private byte[] data;
        public byte checksum;

        public Verbose verbose = Verbose.Quiet;

        public void SetData(int index, byte newdata)
        {
            data[index] = newdata;

            UpdateChecksum();
            record_str = ArrayToRecordString();
        }
        public byte[] Data
        {
            get { return data; }
        }

        int line = 0;

        public UInt16 Address
        {
            get { return address; }
            set { address = value; }
        }


        public UInt32 AddressAbs
        {
            get
            {
                return (address * addressMult + address_offset);
            }
        }
        private UInt32 address_offset;

        public UInt32 AddressOffset
        {
            get { return address_offset; }
            set { address_offset = value; }
        }

        public UInt32 addressMult = 1;

        public static Byte CalcChecksum(byte[] rec)
        {
            int sum = 0;
            int check_sum = 0;
            for (int i = 0; i < (rec.Length - 1); i++)
            {
                sum += rec[i];
            }
            check_sum = (sum ^ 0xff) + 1;
            return (Byte)(check_sum);
        }

        public void UpdateChecksum()
        {
            int len = 1 + 2 + 1 + data.Length + 1; //Byte-count=1,address=2,type=1 + datafield + checksum
            byte[] record = new byte[len];
            record[0] = bytecount;
            record[1] = (byte)(address >> 8);
            record[2] = (byte)(address & 0xff);
            record[4] = (byte)type;
            Array.Copy(data, 0, record, 5, data.Length);

            byte new_sum = CalcChecksum(record);
            checksum = new_sum;
        }
        private String ArrayToRecordString()
        {
            String record_str = ":";
            data_str = "";
            for (int i = 0; i < data.Length; i++)
            {
                data_str += data[i].ToString("X2");
            }
            record_str = ":" + bytecount.ToString("X2") + address.ToString("X4") + ((Byte)type).ToString("X2") + data_str + checksum.ToString("X2");

            return record_str;
        }

        public byte[] GetRecordArray(String s)
        {
            if (s[0] != ':')
                return null;

            byte val = 0;
            byte[] record=new byte[(s.Length-1)/2];
            int recindex = 0;
            for (int i = 1; i < s.Length; i+=2)
            {
                val = Byte.Parse(s.Substring(i,2), System.Globalization.NumberStyles.HexNumber);
                record[recindex++] = val;
            }
            return record;
        }

        public Boolean ParseRecordLine(String s)
        {

            if (String.IsNullOrEmpty(s))
                return false;
            line++;
            record_str = s;
            try
            {
                if (s[0] != ':')
                    return false;

                type_str = record_str.Substring(7, 2);
                type = (RecordType)Byte.Parse(type_str, System.Globalization.NumberStyles.HexNumber);
                if (type == RecordType.EndofFileRecord)
                {
                    if(verbose != Verbose.Quiet)
                        Console.WriteLine("End of file record.");
                    //return true;
                }

                bytecount_str = record_str.Substring(1, 2);
                bytecount = byte.Parse(bytecount_str, System.Globalization.NumberStyles.HexNumber);
                address_str = record_str.Substring(3, 4);

                data_str = record_str.Substring(9, record_str.Length - 9 - 2);
                data = new byte[bytecount];
                for (int i = 0; i < data_str.Length; i += 2)
                {
                    data[i / 2] = Byte.Parse(data_str.Substring(i, 2), System.Globalization.NumberStyles.HexNumber);
                }
                if (type_str == "04")
                {
                    address_offset = UInt32.Parse(data_str.Substring(2, 2), System.Globalization.NumberStyles.HexNumber) << 16;
                }
                if (type_str == "02")
                {
                    uint mul = UInt32.Parse(data_str.Substring(2, 2), System.Globalization.NumberStyles.HexNumber);
                    if (mul != 0)
                        addressMult = mul;
                }
                address = UInt16.Parse(address_str, System.Globalization.NumberStyles.HexNumber);
                checksum_str = record_str.Substring(record_str.Length - 2, 2);
                checksum = Byte.Parse(checksum_str, System.Globalization.NumberStyles.HexNumber);

                byte[] record = GetRecordArray(s);
                byte checksum_calc = CalcChecksum(record);
                if (checksum_calc != checksum)
                {
                    checksumOK = false;
                    Console.WriteLine("Error: Checksum wrong on record {0}. Expected {1X2} <> {2X2}", s, checksum, checksum_calc);
                }
                else
                    checksumOK = true;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
            return true;
        }

    }


    public class IntelHexFile
    {
        List<IntelHexRecord> recordList = new List<IntelHexRecord>(5000);
        int binarysize = 0;
        IntelHexRecord ihex = null;
        int addressoffset_index;
        UInt32 addressoffset;
        UInt32 addressmul = 1;
        UInt32 maxaddress = 0;
        int addressmul_index;
        byte[] binary = null;

        public Verbose verbose = Verbose.Quiet;

        public byte[] Binary
        {
            get { return binary; }
        }

        public int BinarySize
        {
            get { return binarysize; }
        }

        List<IntelHexRecord> RecordList
        {
            get { return recordList; }
        }
                     
        private void CalcActualAddress(IntelHexRecord rec_itm)
        {
            if (rec_itm.type == RecordType.LinearAddressRecord)
            {
                addressoffset_index = recordList.Count - 1;
                addressoffset = rec_itm.AddressOffset;
            }
            if (rec_itm.type == RecordType.SegmentAddressRecord)
            {
                addressmul_index = recordList.Count - 1;
                addressmul = rec_itm.addressMult;
            }
            rec_itm.addressMult = addressmul;
            rec_itm.AddressOffset = addressoffset;
        }

        bool fileValid=false;

        public bool FileValid
        {
            get { return fileValid; }
        }


        public bool LoadFromHexFile(string filepath)
        {
            bool ret = false;
            FileStream hexFs = null;
            StreamReader hexSr = null;
            try
            {
                hexFs = new FileStream(filepath, FileMode.Open, FileAccess.Read);
                hexSr = new StreamReader(hexFs);
                ret = LoadFromHexFile(hexSr);

            }
            catch (Exception ex)
            {
                throw ex;
            }
            finally
            {
                if (hexSr != null)
                    hexSr.Close();
                if (hexFs != null)
                    hexFs.Close();
            }
            return ret;
        }
        /// <summary>
        /// Loads a intel hex file form the file system.
        /// </summary>
        /// <param name="sr">Input is a text streamreader</param>
        /// <returns></returns>
        public bool LoadFromHexFile(StreamReader sr)
        {
            binarysize = 0;
            int lineNr = 0;
            bool retval = false;

            //Read and parse hex file
            if (sr == null)
                return false;
            fileValid = true;

            while (!sr.EndOfStream)
            {
                try
                {

                    String line = sr.ReadLine();

                    ihex = new IntelHexRecord();
                    bool validData = ihex.ParseRecordLine(line);
                    if (!validData)
                    {
                        fileValid = false;
                        continue;
                    }
                    if (!ihex.checksumOK)
                        fileValid = false;
                    if (ihex.type == RecordType.EndofFileRecord)
                    {
                        if (verbose > Verbose.Normal)
                            Console.WriteLine(ihex.type.ToString()+ " at line nr{0}", lineNr);
                    }
                    if (ihex.type == RecordType.LinearAddressRecord)
                    {
                        if (verbose > Verbose.Normal)
                            Console.WriteLine(ihex.type.ToString() + " at line nr{0}", lineNr);
                    }
                    CalcActualAddress(ihex);
                    recordList.Add(ihex);
                    if (ihex.type == RecordType.DataRecord)
                    {
                        if (ihex.AddressAbs > maxaddress)
                            maxaddress = ihex.AddressAbs;

                        if (binarysize < maxaddress)
                            binarysize = (int)maxaddress;
                        binarysize += ihex.Data.Length;
                    }
                    fileValid = true;
                    lineNr++;
                }
                catch (Exception ex)
                {

                    Console.WriteLine("LoadFromHexFile :at line nr{0}" + ex.ToString(), lineNr);
                    retval = false;
                    throw ex;
                }
            }

            binary = new byte[binarysize];//0x020000
            for (int i = 0; i < binary.Length; i++)
                binary[i] = 0xff;


            int binarysize_new = 0;
            int recordindex = 0;
            foreach (IntelHexRecord record in recordList)
            {
                try
                {
                    if (record.type == RecordType.DataRecord)
                    {
                        Array.Copy(record.Data, 0, binary, record.AddressAbs, record.Data.Length);
                        binarysize_new += record.Data.Length;
                    }

                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                    retval = false;
                }
                recordindex++;
            }

            return retval;
        }

        public void WriteCSV(string csvpath)
        {
            //    //String outstr = slen + ";" + address.ToString("X6") + ";" + type + ";" + data + ";" + checksum + ";";
            //    //String outstr = ";\'" + slen + "\';\'" + address.ToString() + "\';\'" + type + "\';\'" + data + "\';\'" + checksum + "\';";
            
            FileStream fs = null;
            StreamWriter sw = null;
            try
            {
                fs = new FileStream(csvpath, FileMode.Create);
                sw = new StreamWriter(fs);

                sw.WriteLine("len;offset;address;address absolute;type;data;checksum");
                foreach (IntelHexRecord rec in recordList)
                {
                    String datastr = "";
                    foreach (byte d in rec.Data)
                    {
                        datastr += d.ToString("X2");
                    }
                    String outstr = rec.bytecount.ToString("X2") + "\';\'" + rec.AddressOffset.ToString("X4") + "\';\'" + rec.Address.ToString("X4") + "\';\'" + rec.AddressAbs.ToString("X8") + "\';\'" + rec.type.ToString() + "\';\'" + datastr + "\';\'" + rec.checksum.ToString("X2");
                    //String outstr = rec.bytecount.ToString("X2") + ";" + rec.AddressOffset.ToString("X4") + ";" + rec.Address.ToString("X4") + ";" + rec.AddressAbs.ToString("X8") + ";" + rec.type.ToString() + ";" + datastr + ";" + rec.checksum.ToString("X2");
                    sw.WriteLine(outstr);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
            finally
            {
                if (sw != null)
                    sw.Close();
                if (fs != null)
                    fs.Close();
            }

        }

        public void WriteBinary(string binpath)
        {
            FileStream fsBin = null;
            BinaryWriter bw = null;
            try
            {
                fsBin = new FileStream(binpath, FileMode.Create, FileAccess.Write);
                bw = new BinaryWriter(fsBin);
                bw.Write(binary);
                bw.Close();
                fsBin.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
            finally
            {
                if (bw != null)
                    bw.Close();
                if (fsBin != null)
                    fsBin.Close();
            }
        }

        public void WriteHex(string outpath)
        {
            FileStream fsout = null;
            StreamWriter sw = null;
            try
            {
                fsout = new FileStream(outpath, FileMode.Create, FileAccess.Write);
                sw = new StreamWriter(fsout);

                foreach (IntelHexRecord rec in recordList)
                {
                    sw.WriteLine(rec.RecordString);
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
            finally
            {
                if (sw != null)
                    sw.Close();
                if (fsout != null)
                    fsout.Close();
            }

        }

        public void SetByte(UInt32 address, byte newdata)
        {
            int index = 0, data_idx = 0;
            for (int i = 0; i < recordList.Count; i++)
            {
                if (recordList[i].AddressAbs == address)
                {
                    index = i;
                    data_idx = 0;
                    break;
                }
                else if ((recordList[i].AddressAbs + recordList[i].bytecount) > address)  //liegt noch innerhalb des aktuellen records
                {
                    index = i;
                    var val =  recordList[i].AddressAbs - address;
                    data_idx = Convert.ToInt32(address - recordList[i].AddressAbs);
                    break;
                }
                else if (recordList[i].AddressAbs > address)  //liegt noch innerhalb des letzten records
                {
                    index = i - 1;
                    data_idx = Convert.ToInt32(recordList[i].AddressAbs - address);
                    break;
                }
            }
            recordList[index].SetData(data_idx, newdata);
            binary[address] = newdata;
        }

        public byte GetByte(UInt32 address)
        {
            int index;
            byte data = 0;
            int data_idx;
            for (int i = 0; i < recordList.Count; i++)
            {
                if (recordList[i].AddressAbs == address)
                {
                    index = i;
                    data = recordList[i].Data[0];
                    break;
                }
                else if ((recordList[i].AddressAbs + recordList[i].bytecount) > address)  //liegt noch innerhalb des aktuellen records
                {
                    index = i-1;
                    data_idx = Convert.ToInt32(address - recordList[i-1].AddressAbs);
                    data = recordList[index].Data[data_idx];
                    break;
                }
                else if (recordList[i].AddressAbs > address)  //liegt noch innerhalb des letzten records
                {
                    index = i - 1;
                    data_idx = Convert.ToInt32(recordList[i].AddressAbs - address);
                    data = recordList[index].Data[data_idx];
                    break;
                }
            }

            return data;
        }
    }

}
