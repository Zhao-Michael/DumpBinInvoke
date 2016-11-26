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

        private void mbuttonExec_Click(object sender, RoutedEventArgs e)
        {
            if (mTextBoxPath.Text == string.Empty) return;

            GetOutput(mHeaderBox, mTextBoxPath.Text, " /HEADERS");
            GetOutput(mAsmHeader, mTextBoxPath.Text, " /DISASM");
            GetOutput(mExports, mTextBoxPath.Text, " /EXPORTS");
            GetOutput(mDependents, mTextBoxPath.Text, " /DEPENDENTS");
            GetOutput(mImports, mTextBoxPath.Text, " /IMPORTS");
            GetOutput(mRowData, mTextBoxPath.Text, " /RAWDATA");
            GetOutput(mReLocations, mTextBoxPath.Text, " /RELOCATIONS");

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

        public static void GetOutput(TextBox textbox, string dllpath, string arg)
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

            process.OutputDataReceived += (o, e) =>
            {
                temp = temp + e.Data + Environment.NewLine;

                textbox.Dispatcher.BeginInvoke(new Action(() => textbox.Text = temp), null);

            };
            process.BeginOutputReadLine();
            process.Start();

        }


        public static string GetShortName(string sLongFileName)
        {
            var buffer = new StringBuilder(259);
            int len = GetShortPathName(sLongFileName, buffer, buffer.Capacity);
            if (len == 0) throw new System.ComponentModel.Win32Exception();
            return buffer.ToString();
        }

        [DllImport("kernel32", EntryPoint = "GetShortPathName", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int GetShortPathName(string longPath, StringBuilder shortPath, int bufSize);


        private void Window_DragEnter(object sender, DragEventArgs e)
        {
            mTextBoxPath.Text = ((System.Array)e.Data.GetData(DataFormats.FileDrop)).GetValue(0).ToString();
        }


    }



}
