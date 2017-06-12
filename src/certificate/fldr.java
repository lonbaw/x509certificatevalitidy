package certificate;


	

	import java.io.File;

	import javax.swing.JFileChooser;
	import javax.swing.filechooser.FileSystemView;

	public class fldr {

	public static String fldr(){
	int result = 0;
	File file = null;
	String path = null;
	JFileChooser fileChooser = new JFileChooser();
	FileSystemView fsv = FileSystemView.getFileSystemView();  //注意了，这里重要的一句
    fileChooser.setCurrentDirectory(fsv.getHomeDirectory());
	fileChooser.setDialogTitle("请选择要上传的文件...");
	fileChooser.setApproveButtonText("确定");
	fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
	result = fileChooser.showOpenDialog(fileChooser);
	if (JFileChooser.APPROVE_OPTION == result) {
	    	   path=fileChooser.getSelectedFile().getPath();
	    	   
	   }
	return path;
	}}
	
	
	

