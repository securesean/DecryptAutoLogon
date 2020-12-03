// C$# implementation of https://keithga.wordpress.com/2013/12/19/sysinternals-autologon-and-securely-encrypting-passwords/
// And from https://www.pinvoke.net/default.aspx/advapi32/LsaOpenPolicy.html
using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

namespace DecryptAutoLogon
{
    class Program
    {
        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int MessageBox(IntPtr hWnd, string lpText, string lpCaption, uint uType);


        // This was started from the sample code above (which I originally found on code project). Then https://www.pinvoke.net/default.aspx/advapi32/LsaOpenPolicy.html

        public class LSAStringMarshaler : ICustomMarshaler
        {
            System.Collections.Hashtable myAllocated = new System.Collections.Hashtable();

            private static LSAStringMarshaler marshaler = new LSAStringMarshaler();
            public static ICustomMarshaler GetInstance(string cookie)
            {
                return marshaler;
            }

            public object MarshalNativeToManaged(System.IntPtr pNativeData)
            {
                if (pNativeData != IntPtr.Zero)
                {
                    LSA_UNICODE_STRING lus = (LSA_UNICODE_STRING)Marshal.PtrToStructure(pNativeData, typeof(LSA_UNICODE_STRING));
                    return lus.ToString();
                }
                return null;
            }

            private static readonly int nativeSize = IntPtr.Size + sizeof(UInt16) + sizeof(UInt16);

            public System.IntPtr MarshalManagedToNative(object ManagedObj)
            {
                LSA_UNICODE_STRING lus = new LSA_UNICODE_STRING();
                IntPtr memory = Marshal.AllocHGlobal(nativeSize);
                myAllocated[memory] = memory;
                //Console.WriteLine("MarshalManagedToNative");
                lus.SetTo((string)ManagedObj);
                Marshal.StructureToPtr(lus, memory, true);
                return memory;
            }

            public void CleanUpManagedData(object ManagedObj)
            {
                //Console.WriteLine("CCC Cleanup Managed Data");            
            }

            public int GetNativeDataSize()
            {
                return nativeSize;
            }

            public void CleanUpNativeData(System.IntPtr pNativeData)
            {
                //Console.WriteLine("CCC Cleanup Native Data");            

                if (myAllocated.ContainsKey(pNativeData))
                {
                    myAllocated.Remove(pNativeData);
                    LSA_UNICODE_STRING lus = (LSA_UNICODE_STRING)Marshal.PtrToStructure(pNativeData, typeof(LSA_UNICODE_STRING));
                    lus.Clean();
                    Marshal.FreeHGlobal(pNativeData);
                }
            }
        }

        [DllImport("advapi32.dll")]
        private static extern UInt32 LsaRetrievePrivateData(
        IntPtr policyHandle,
        [MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(LSAStringMarshaler))] string KeyName,
        [MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(LSAStringMarshaler))] ref string PrivateData
        );


        [StructLayout(LayoutKind.Sequential)]
        internal struct LSA_UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;

            public void SetTo(string str)
            {
                Buffer = Marshal.StringToHGlobalUni(str);
                Length = (UInt16)(str.Length * UnicodeEncoding.CharSize);
                MaximumLength = (UInt16)(Length + UnicodeEncoding.CharSize);
                //Console.WriteLine("SetTo: {2} ({3}) Length: {0} Max: {1}", Length, MaximumLength, str, str.Length);
            }

            public override string ToString()
            {
                string str = Marshal.PtrToStringUni(Buffer, Length / UnicodeEncoding.CharSize);
                //Console.WriteLine("ToString: {2} ({3}) Length: {0} Max: {1}", Length, MaximumLength, str, str.Length);
                return str;
            }

            public void Clean()
            {
                //Console.WriteLine("Clean Length: {0} Max: {1}", Length, MaximumLength);
                if (Buffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(Buffer);
                Buffer = IntPtr.Zero;
                Length = 0;
                MaximumLength = 0;
            }
        };

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public LSA_UNICODE_STRING ObjectName;
            public UInt32 Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [DllImport("advapi32.dll")]
        private static extern UInt32 LsaNtStatusToWinError(UInt32 status);

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        static extern uint LsaOpenPolicy(
           ref LSA_UNICODE_STRING SystemName,
           ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
           uint DesiredAccess,
           out IntPtr PolicyHandle
        );

        static void Main(string[] args)
        {
            // LsaOpenPolicy function opens a handle to the Policy object on a local or remote system.
            //initialize an empty unicode-string
            LSA_UNICODE_STRING aSystemName = new LSA_UNICODE_STRING();

            //these attributes are not used, but LsaOpenPolicy wants them to exists
            LSA_OBJECT_ATTRIBUTES aObjectAttributes = new LSA_OBJECT_ATTRIBUTES();


            //these attributes are not used, but LsaOpenPolicy wants them to exist
            // (MSDN: "the structure members are not used, initalize them to NULL or zero")
            LSA_OBJECT_ATTRIBUTES ObjectAttributes = new LSA_OBJECT_ATTRIBUTES();
            ObjectAttributes.Length = 0;
            ObjectAttributes.RootDirectory = IntPtr.Zero;
            ObjectAttributes.Attributes = 0;
            ObjectAttributes.SecurityDescriptor = IntPtr.Zero;
            ObjectAttributes.SecurityQualityOfService = IntPtr.Zero;

            // This was hard coded in keithga's binary - https://docs.microsoft.com/en-us/windows/win32/secauthz/access-mask
            uint access = 1;

            // A pointer to an LSA_HANDLE variable that receives a handle to the Policy object.
            IntPtr policy = IntPtr.Zero;

            //get a policy handle
            UInt32 resultPolicy = LsaOpenPolicy(ref aSystemName, ref ObjectAttributes, access, out policy);
            UInt32 winErrorCode = LsaNtStatusToWinError(resultPolicy);

            if (resultPolicy != 0)
            {
                Console.WriteLine("OpenPolicy failed: " + resultPolicy);
            }

            if (winErrorCode != 0)
            {
                Console.WriteLine("OpenPolicy Error: " + winErrorCode);
            }

            string result = RetrievePrivateData("DefaultPassword", policy);

            Console.WriteLine("AutoLogon Password: " + result);
        }

        public static string RetrievePrivateData(string key, IntPtr policy)
        {
            string result = null;
            UInt32 ntstatus = LsaRetrievePrivateData(policy, key, ref result);
            UInt32 winErrorCode = LsaNtStatusToWinError(ntstatus);
            if (winErrorCode != 0)
            {
                Console.WriteLine("RetreivePrivateData failed: " + winErrorCode);
                return "";
            }
            return result;
        }
    }
}
