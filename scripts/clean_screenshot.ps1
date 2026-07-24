param(
    [Parameter(Mandatory=$true)][string]$OutPath,
    [int]$ChromePid = 2776,
    [int]$TopCrop = 215,
    [int]$BottomCrop = 78,
    [int]$SideCrop = 28
)
Add-Type -AssemblyName System.Windows.Forms,System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class CleanShotWin32c {
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [StructLayout(LayoutKind.Sequential)]
    public struct INPUT { public uint type; public MOUSEINPUT mi; }
    [StructLayout(LayoutKind.Sequential)]
    public struct MOUSEINPUT {
        public int dx; public int dy; public uint mouseData; public uint dwFlags; public uint time; public IntPtr dwExtraInfo;
    }
    [DllImport("user32.dll")] public static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);
    public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
    public const uint MOUSEEVENTF_MOVE = 0x0001;
    public const uint MOUSEEVENTF_ABSOLUTE = 0x8000;
    public const uint MOUSEEVENTF_VIRTUALDESK = 0x4000;
    public static void MoveAbsolute(int x, int y, int screenW, int screenH) {
        int nx = (int)((x * 65535L) / screenW);
        int ny = (int)((y * 65535L) / screenH);
        INPUT[] inputs = new INPUT[1];
        inputs[0].type = 0; // INPUT_MOUSE
        inputs[0].mi = new MOUSEINPUT { dx = nx, dy = ny, mouseData = 0, dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE, time = 0, dwExtraInfo = IntPtr.Zero };
        SendInput(1, inputs, Marshal.SizeOf(typeof(INPUT)));
    }
}
"@
$p = Get-Process -Id $ChromePid
$hwnd = $p.MainWindowHandle
[CleanShotWin32c]::SetForegroundWindow($hwnd) | Out-Null
Start-Sleep -Milliseconds 300
$screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
[CleanShotWin32c]::MoveAbsolute($screen.Width - 3, $screen.Height - 3, $screen.Width, $screen.Height)
Start-Sleep -Milliseconds 400
$rect = New-Object CleanShotWin32c+RECT
[CleanShotWin32c]::GetWindowRect($hwnd, [ref]$rect) | Out-Null
$w = $rect.Right - $rect.Left
$h = $rect.Bottom - $rect.Top
$bmp = New-Object System.Drawing.Bitmap $w,$h
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($rect.Left, $rect.Top, 0, 0, $bmp.Size)
$g.Dispose()
$cropW = $w - (2*$SideCrop)
$cropH = $h - $TopCrop - $BottomCrop
$cropRect = New-Object System.Drawing.Rectangle $SideCrop,$TopCrop,$cropW,$cropH
$cropped = $bmp.Clone($cropRect, $bmp.PixelFormat)
$cropped.Save($OutPath, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose(); $cropped.Dispose()
Write-Output "Saved: $OutPath"
