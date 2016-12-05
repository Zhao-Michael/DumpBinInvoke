using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace DumpBinInvoke
{
    /// <summary>
    /// MainWindow.xaml 的交互逻辑
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        public static string mAsmContent = string.Empty;
        public static string mRawContent = string.Empty;

        private void mbuttonExec_Click(object sender, RoutedEventArgs e)
        {

            if (mTextBoxPath.Text == string.Empty) return;

            GetOutput(mHeaderBox, mTextBoxPath.Text, " /HEADERS");
            GetOutput(mAsmHeader, mTextBoxPath.Text, " /DISASM", true);
            GetOutput(mExports, mTextBoxPath.Text, " /EXPORTS");
            GetOutput(mDependents, mTextBoxPath.Text, " /DEPENDENTS");
            GetOutput(mImports, mTextBoxPath.Text, " /IMPORTS");
            GetOutput(mRowData, mTextBoxPath.Text, " /RAWDATA", true);
            GetOutput(mReLocations, mTextBoxPath.Text, " /RELOCATIONS");

            if (mTextBoxPath.Text.ToLower().EndsWith(".exe"))
            {
                MonitorProcess();

                mTabControl.SelectedIndex = mTabControl.Items.Count - 1;
            }

        }


        private void mButtonOpen_Click(object sender, RoutedEventArgs e)
        {
            System.Windows.Forms.OpenFileDialog open = new System.Windows.Forms.OpenFileDialog();
            open.Multiselect = false;
            open.Title = "选择执行文件";
            open.CheckFileExists = true;
            open.Filter = "所有文件|*.*|可执行文件|*.exe|静态链接库|*.lib|动态链接库|*.dll|中间目标文件|*.obj";

            if (open.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                mTextBoxPath.Text = open.FileName;
            }

        }


        public List<T> GetChildObjects<T>(DependencyObject obj, Action<T> actor = null) where T : FrameworkElement
        {
            DependencyObject child = null;

            List<T> childList = new List<T>();

            for (int i = 0; i <= VisualTreeHelper.GetChildrenCount(obj) - 1; i++)
            {
                child = VisualTreeHelper.GetChild(obj, i);

                if (child is T && (((T)child).GetType() == typeof(T)))
                {
                    actor?.Invoke((T)child);

                    childList.Add((T)child);
                }
                childList.AddRange(GetChildObjects<T>(child, actor));
            }



            return childList;
        }


        public void MonitorProcess()
        {
            mExeOutput.Text = string.Empty;

            ProcessStartInfo startInfo = new ProcessStartInfo(mTextBoxPath.Text)
            {
                WindowStyle = ProcessWindowStyle.Hidden,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };

            Func<string> mGetTime = () =>
            {
                return DateTime.Now.ToString("[ yyyy-MM-dd HH::mm::ss::fff ] ");
            };

            Process process = Process.Start(startInfo);
            process.OutputDataReceived += (o, e1) =>
            {
                mExeOutput.Dispatcher.BeginInvoke(new Action(() =>
                {
                    mExeOutput.Text += mGetTime() + e1.Data + Environment.NewLine;
                    mExeOutput.SelectionStart = mExeOutput.Text.Length;
                    mExeOutput.ScrollToEnd();
                }), null);
            };
            process.BeginOutputReadLine();

        }


        public void GetOutput(TextBox textbox, string dllpath, string arg, bool lenText = false)
        {
            textbox.Text = string.Empty;

            ProcessStartInfo startInfo = new ProcessStartInfo("cmd.exe", "/c " + "dumpbin.exe " + GetShortName(dllpath) + arg)
            {
                WindowStyle = ProcessWindowStyle.Hidden,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };

            Process process = Process.Start(startInfo);

            string temp = string.Empty;

            if (lenText)
            {
                if (textbox == mAsmHeader)
                {
                    process.OutputDataReceived += (o, e) =>
                    {
                        temp = temp + e.Data + Environment.NewLine;

                        textbox.Dispatcher.BeginInvoke(new Action(() => mAsmContent = temp), null);

                    };
                }
                else if (textbox == mRowData)
                {
                    process.OutputDataReceived += (o, e) =>
                    {
                        temp = temp + e.Data + Environment.NewLine;

                        textbox.Dispatcher.BeginInvoke(new Action(() => mRawContent = temp), null);

                    };
                }

            }
            else
            {
                process.OutputDataReceived += (o, e) =>
                {
                    temp = temp + e.Data + Environment.NewLine;

                    textbox.Dispatcher.BeginInvoke(new Action(() => textbox.Text = temp), null);

                };
            }

            process.BeginOutputReadLine();
            process.Start();

        }


        public static string GetShortName(string sLongFileName)
        {
            var buffer = new StringBuilder(259);
            int len = DllHandler.GetShortPathName(sLongFileName, buffer, buffer.Capacity);
            if (len == 0) throw new System.ComponentModel.Win32Exception();
            return buffer.ToString();
        }


        private void mTabControl_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (mTabControl.SelectedItem == mRawItem)
            {
                mRowData.Text = mRawContent;
            }
            else if (mTabControl.SelectedItem == mAsmItem)
            {
                mAsmHeader.Text = mAsmContent;
            }
        }


        private void Window_DragEnter(object sender, DragEventArgs e)
        {
            try
            {
                mTextBoxPath.Text = ((System.Array)e.Data.GetData(DataFormats.FileDrop)).GetValue(0).ToString();

            }
            catch (Exception ex)
            {
                mTextBoxPath.Text = "";
                MessageBox.Show(ex.Message);
            }
        }


        private void Window_DragOver(object sender, DragEventArgs e)
        {
            e.Effects = DragDropEffects.Copy;

            e.Handled = true;
        }


        private void Window_Drag(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                // do whatever you want do with the dropped element
                System.Array droppedThingie = e.Data.GetData(DataFormats.FileDrop) as System.Array;
            }
        }


    }

    public class DllHandler
    {

        [DllImport("DecryptSymbolName.dll", EntryPoint = "DecryptSymbolName", SetLastError = true)]
        public extern static int DecryptSymbolName(string srcname, StringBuilder realname);

        [DllImport("kernel32", EntryPoint = "GetShortPathName", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int GetShortPathName(string longPath, StringBuilder shortPath, int bufSize);

        public static string GetDecryptSymbolName(string src)
        {
            //"?FindEdge@IPCV@@YAXVMat@cv@@V?$Rect_@H@3@HH_NW4SEARCHDIRECTION@@AAUEdgeFindResult@@@Z"

            var sb = new StringBuilder();

            DecryptSymbolName(src, sb);

            return sb.ToString();
        }
    }


}
