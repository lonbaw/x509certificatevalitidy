package certificate;



import javax.net.ssl.HttpsURLConnection;
import javax.swing.*;
import javax.swing.*;

import com.alibaba.fastjson.JSON;
import com.google.gson.Gson;

import sun.misc.BASE64Decoder;

import java.awt.*;
import java.awt.event.*;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Principal;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class jiemian extends JFrame implements ActionListener {
 private Panel pan,pan1,pan2,pan3;
 private JTextField aField;
 private static  JTextArea bField;
 private JButton b;

 static int bolean =1;



	
	//验证证书时间有效性算法
	public static boolean time_analysis(String Notbefore,String Notend) throws ParseException{
	      //进行格式转化，转化UTC格式
			String start = Notbefore.replace("Z", " UTC");//注意是空格+UTC
	    	String end=Notend.replace("Z", " UTC");
	        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");//注意格式化的表达式
	        Date kaishi = format.parse(start);
	        Date jieshu = format.parse(end);
	      //获取当前时间
	        Date now =new Date();  
	        bField.append("系统当前时间"+now+"\n");
	       // System.out.println("系统当前时间"+now);
		
	        //国内证书一般为1~2年，所以要验证是否超时
	          if((jieshu.getTime()/1000)- (kaishi.getTime()/1000) > 63072000){
	        	  bField.append("--------证书有效期过长，无效！----------"+"\n");
	        	  //System.out.println("--------证书有效期过长，无效！----------"+"\n");
	        	  return false;
	          }else if(now.getTime() > kaishi.getTime() && now.getTime() < jieshu.getTime()){
	        	  bField.append("--------证书在有效期内，可正常使用！---------"+"\n");
	        	//System.out.println("--------证书在有效期内，可正常使用！---------"+"\n");
	        	return true;
	          }else
	        	  bField.append("--------证书还未生效或者已过期！----"+"\n");
	    	 // System.out.println("--------证书还未生效或者已过期！----"+"\n");
	          return false;
	}
	

		//验证RSA签名算法
		
		/**
	     * Verify
	     *
	     * @param data //签名内容
	     * @param sign //签名后的值
     * @param publickey 公钥
	     * @return
	     * @throws Exception
	     */
		
	     public static boolean Verify(String data, String sign, PublicKey publickey ) throws Exception{
	    	   // BigInteger mbig = new BigInteger(mod, 16);
				//BigInteger ebig = new BigInteger(exp, 16);
	    	// RSAPublicKeySpec spec = new RSAPublicKeySpec(mbig, ebig);
	        // KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	       //  java.security.PublicKey verifyKey = keyFactory.generatePublic(spec);
	         Signature verifier = Signature.getInstance("SHA256withRSA");	
	         verifier.initVerify(publickey);  	
	         verifier.update(hexString2ByteArray(data));
	         System.out.println("hexString2ByteArray(data)"+hexString2ByteArray(data));
	         System.out.println("hexString2ByteArray(sign)"+hexString2ByteArray(sign));
	         return verifier.verify(hexString2ByteArray(sign));
	     }

	     public static byte[] hexString2ByteArray(String hexStr){
	         if (hexStr == null)
	             return null;
	         if (hexStr.length() % 2 != 0)
	             return null;
	         byte data[] = new byte[hexStr.length() / 2];
	         for (int i = 0; i < hexStr.length() / 2; i++){
	             char hc = hexStr.charAt(2 * i);
	             char lc = hexStr.charAt(2 * i + 1);
	             byte hb = hexChar2Byte(hc);
	             byte lb = hexChar2Byte(lc);
	             if (hb < 0 || lb < 0)
	                 return null;
	             int n = hb << 4;
	             data[i] = (byte)(n + lb);
	         }
	        return data;
	    }

	    public static byte hexChar2Byte(char c){
	        if (c >= '0' && c <= '9')
	            return (byte)(c - 48);
	        if (c >= 'a' && c <= 'f')
	            return (byte)((c - 97) + 10);
	        if (c >= 'A' && c <= 'F')
	            return (byte)((c - 65) + 10);
	        else
	            return -1;
	    }

	/*
		// 通过公钥byte[]将公钥还原，适用于RSA算法 
public static  PublicKey getPublicKey(String modulus, String publicExponent) throws NoSuchAlgorithmException, InvalidKeySpecException { 
    
	    BigInteger bigIntModulus = new BigInteger(modulus,16); 
	    System.out.println("getpublickey中的模数转化后"+bigIntModulus);
    BigInteger bigIntPrivateExponent = new BigInteger(publicExponent,16); 
    System.out.println("getpublickey中的指数转化后"+bigIntPrivateExponent);
    RSAPublicKeySpec keySpec = new RSAPublicKeySpec(bigIntModulus, bigIntPrivateExponent); 
    KeyFactory keyFactory = KeyFactory.getInstance("RSA"); 
    PublicKey publicKey = keyFactory.generatePublic(keySpec); 
    System.out.println("转化之后的公钥"+publicKey);
     return publicKey; 

				 } 
				 */
/**
* 校验数字签名
*/

private static byte[] decryptBASE64(String key) {
	// TODO Auto-generated method stub
	byte[] bytes = null;
	try {
		bytes = (new BASE64Decoder()).decodeBuffer(key);
	} catch (IOException e) {
		e.printStackTrace();
	}
	return bytes;
}
	
/**
* decode by Base64 
**/  
public static byte[] decodeBase64(String input) throws Exception{  
  Class clazz=Class.forName("com.sun.org.apache.xerces.internal.impl.dv.util.Base64");  
  Method mainMethod= clazz.getMethod("decode", String.class);  
  mainMethod.setAccessible(true);  
  Object retObj=mainMethod.invoke(null, input);  

  return (byte[])retObj;  
}  
/**
*验证crl中的签名 
**/
public static void VerifyCRLSignature(String stURL,BigInteger certSN,RSAPublicKey publickey) throws  IOException {

URL url = new URL(stURL);

// Open connection
HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
 bField.append("\n"+"（三）验证crl里的签名"+"\n"+"开始下载CRL...."+"\n");

try {
    // Get .crtFile
    InputStream in = new BufferedInputStream(urlConnection.getInputStream());
    
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    bField.append("CRL下载成功"+"\n"+"\n");

    X509CRL crl = (X509CRL) cf.generateCRL(in);
    byte[] signature = crl.getSignature();
    bField.append("提取CRL签名信息:"+signature+"\n");
    bField.append("验证CRL签名:"+"\n"+"\n");

    
     try{ crl.verify(publickey);
     bField.append("crl签名验证成功"+"\n");
  
     } catch (Exception e) {
    	 bField.append("crl签名验证失败"+"\n");
        }
}
     catch (Exception e) {
    	 bField.append("uri"+"失败！请重新尝试"+"\n");
}
finally {
        urlConnection.disconnect();
}
}
/**
*验证crl的时间有效？以及验证证书是否撤销 
**/
public static boolean GetCRL(String stURL,BigInteger certSN) throws  IOException {

URL url = new URL(stURL);

// Open connection
HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
 //System.out.println("建立url链接....");
try {
    // Get .crtFile
    InputStream in = new BufferedInputStream(urlConnection.getInputStream());
   // System.out.println("获得输入流.....");
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
   // System.out.println("输出证书工厂.....");
    X509CRL crl = (X509CRL) cf.generateCRL(in);
   // System.out.println("输出证书撤销列表有关信息:"+crl);
    //System.out.println("All revoked: "+crl.getRevokedCertificates().toString());

    // Test what certificate? Serial number   
    //System.out.println("序列号十进制表示: "+certSN.toString()+"\n");
    // See if revoked  
    X509CRLEntry isRevoked = crl.getRevokedCertificate(certSN);
    Date thisupdate = crl.getThisUpdate();
    bField.append( "（三）验证CRL的日期："+"\n");
    bField.append("CRL生效时间"+thisupdate+"\n");
    Date nextupdate = crl.getNextUpdate();
    bField.append("CRL下次更新时间"+nextupdate +"\n");
 
    Date now =new Date();
    bField.append("系统时间"+now +"\n");
    bField.append("验证CRL是否生效:"+"\n");
    
    if(thisupdate.getTime()< now.getTime()&& now.getTime()<nextupdate.getTime()){
    	bField.append("CRL当前在有效期内"+"\n");
    	bField.append("（三）验证CRL中是否含有当前证书序列号"+"\n");
    	bField.append("Revoking（撤销状态查询）:"+"\n");

    if (isRevoked != null) {
    	bField.append("已经被撤销！"+"\n"+"=================="+"\n"+"撤销序列号为： "+isRevoked.toString());
        return true;
    } else {
    	bField.append("没有被撤销！"+"\n"+"==================");
       return false;
    }
    }else
    	bField.append("--------CRL还未生效-----------");

    return true;

} catch (Exception e) {
	bField.append("uri"+"失败！请重新尝试");

}
finally {
        urlConnection.disconnect();
}
return false;
}
/**
* 获取上级证书的公钥
* **/
public static RSAPublicKey getlastpublickey(String public_url) throws  IOException {
	 URL url = new URL(public_url);

	    // Open connection
	    HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
	    bField.append("通过证书链下载颁发者公钥"+"\n");
	     //System.out.println("通过证书链下载颁发者公钥");
	
     try{
    	 InputStream in = new BufferedInputStream(urlConnection.getInputStream());
       
         CertificateFactory cf = CertificateFactory.getInstance("X.509");
        
         //System.out.println("输出证书工厂...."+"\n");
         Certificate x509 =  cf.generateCertificate(in);
       //  System.out.println("证书"+x509);
         RSAPublicKey pub = (RSAPublicKey) x509.getPublicKey();
       //  String modulus = pub.getModulus().toString(16);
         bField.append("公钥下载成功"+"\n");
        // System.out.println("公钥下载成功");
          //System.out.println("<<<<<<<<<<<<<<<<<<<<<<<<已经获取到公钥>>>>>>>>>>>>>>>>>>>>>"+"\n");
         bField.append("公钥:"+pub);
         // System.out.println("公钥:"+pub);
         return pub;
        // System.out.println("modulus:"+pub.getModulus().toString(16));
         //System.out.println("exponent:"+pub.getPublicExponent().toString(16));
        //System.out.println("获取公钥"+x509.getPublicKey());
     } catch (Exception e) {
    	 bField.append("uri"+"失败！请重新尝试");
        // System.out.println("uri"+"失败！请重新尝试");
     }
     finally {
             urlConnection.disconnect();
     }
		return null;


}


private static final char[] DIGITS
= {'0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

public static final String toHex(byte[] data) {
final StringBuffer sb = new StringBuffer(data.length * 2);
for (int i = 0; i < data.length; i++) {
sb.append(DIGITS[(data[i] >>> 4) & 0x0F]);
sb.append(DIGITS[data[i] & 0x0F]);
}
return sb.toString();
}

//获取证书链
public static boolean testConnectionTo(String aURL) throws Exception {
	URL destinationURL = new URL(aURL);
	HttpsURLConnection conn = (HttpsURLConnection) destinationURL.openConnection();
	conn.connect();
	Certificate[] certs = conn.getServerCertificates();
	ArrayList<BigInteger> list=new ArrayList<BigInteger>();
	Principal principalLast=null;
	bField.append("（二）证书完整性验证"+"\n");
	bField.append("获取证书链"+"\n");
	bField.append("除去根证书外的证书链条长度"+certs.length+"\n");
	//System.out.println("（二）证书完整性验证"+"\n"+"=========================");
	//System.out.println("获取证书链"+"\n"+"=========================");
	//System.out.println("除去根证书外的证书链条长度"+certs.length);
	for(int i=0;i<certs.length;i++){
		X509Certificate x509Certificate=(X509Certificate) certs[i];
		bField.append("显示颁发者拥有者信息"+"\n");
		//System.out.println("显示颁发者拥有者信息"+"\n"+"=========================");
		//获取发布者标识
		Principal principalIssuer=x509Certificate.getIssuerDN();
		bField.append("issuer:"+principalIssuer+"\n");
		//System.out.println("issuer:"+principalIssuer);
		//获取证书的主体标识
		Principal principalSubject=x509Certificate.getSubjectDN();
		bField.append("subject:"+principalSubject+"\n");
		//System.out.println("subject:"+principalSubject);
		bField.append("----------------------"+"\n");
		//System.out.println("----------------------");
		//if(principalIssuer.equals(principalSubject)){
		//	System.out.println("this is ROOT CA");}
		//保存证书的序列号
		list.add(x509Certificate.getSerialNumber());
		if(principalLast!=null){
		//验证证书的颁布者是上一个证书的所有者
			bField.append("开始沿证书链自下而上验证"+"\n");
			bField.append("验证当前证书的颁布者是下一个证书的所有者"+"\n");
			//System.out.println("开始沿证书链自下而上验证"+"\n"+"=========================");
			//System.out.println("验证当前证书的颁布者是下一个证书的所有者"+"\n"+"====================");
		if(principalSubject.equals(principalLast)){
			bField.append("验证CA的签名"+"\n");
			//System.out.println("验证CA的签名"+"\n"+"====================");
		try{
		//获取上个证书的公钥
		PublicKey publickey=certs[i].getPublicKey();
		bField.append("获取颁发者CA的公钥："+publickey +"\n");
		//System.out.println("获取颁发者CA的公钥："+publickey +"\n"+"====================");
	 byte[]sign=((X509Certificate) certs[i-1]).getSignature();
	 bField.append("获取当前证书的签名："+sign +"\n");
	//System.out.println("获取当前证书的签名："+sign +"\n"+"====================");
		//验证签名
		certs[i-1].verify(publickey);   	
		bField.append("证书签名验证：success！");
		//System.out.println("证书签名验证：success！");
		 int bolean = 1;
		}catch(Exception e){
			bField.append("error");
			//System.out.println("error");
			int bolean = 0;
			 if(bolean==0){
				   return false;
			  }
		}
		
		}//if(principalIssuer.equals(principalLast))
		 
			
		
		}//if(principalLast!=null)
		principalLast=principalIssuer;
		
	

		
}//for
	return true;
}//fangfa
  

//读取本地证书文件算法
		public static List<String> readTxtFile(String filePath){
			List<String> json = new ArrayList<String>();
	        try {
		        String encoding="GBK";
		        File file=new File(filePath);
		        if(file.isFile() && file.exists()){ //判断文件是否存在
		            InputStreamReader read = new InputStreamReader(
		            new FileInputStream(file),encoding);//考虑到编码格式
		            BufferedReader bufferedReader = new BufferedReader(read);
		            String lineTxt = null;
		            while((lineTxt = bufferedReader.readLine()) != null){
//		                System.out.println(lineTxt);
		            	json.add(lineTxt);
		            }
	            read.close();
			    }else{
			        System.out.println("找不到指定的文件");
			    }
	        } catch (Exception e) {
	            System.out.println("读取文件内容出错");
	            e.printStackTrace();
	        } finally {
				return json;
			}
	        
	     
	    }
 

 jiemian(){
	 
 this.setBounds(0,0,500,480);
 pan=new Panel();
 pan1=new Panel();
 pan2=new Panel();
 pan3=new Panel();
 this.setTitle("证书有效性分析");
 

 b=new JButton("打开文件");
 b.addActionListener(this);
 aField=new JTextField(32);
 bField=new JTextArea(20,40);
 JScrollPane js=new JScrollPane(bField);
 pan1.add(aField);

 pan2.add(b);
 pan3.add(js);
 pan.add(pan1);
 pan.add(pan2);
 pan.add(pan3);
 add(pan);
 
 this.setAlwaysOnTop(true);
 this.setVisible(true);
 }
 
 public static void main(String args[]){
 new jiemian();
 }

@Override
public void actionPerformed(ActionEvent e) {
	
	if(e.getSource()==b){

		 String[] aString=null;
		String filename2=fldr.fldr();
		//String path=fldr.fldr();
	
		  aField.setText(filename2);
		  List<String> falselist = new ArrayList<String>();
		  List<String> notvalitidylist = new ArrayList<String>();
			 List<String> jsonlist = null;
		
			jsonlist = readTxtFile(filename2);
			String sizejson =String.valueOf(jsonlist.size());
	    bField.append("证书总数目"+sizejson+"\n");
	    for(int i = 0; i < jsonlist.size(); i++){
			String str = jsonlist.get(i);
			HashMap jsonob = JSON.parseObject(str,HashMap.class);
	    //huoqu raw
			String raw = jsonob.get("raw").toString();
			//System.out.println(raw);
			Object par = jsonob.get("parsed");
			HashMap jsonob1 = JSON.parseObject(par.toString(),HashMap.class);
	     //获取序列号
			String serial = jsonob1.get("serial_number").toString();
			String vers = jsonob1.get("version").toString();
			//System.out.println("xuliehao:"+serial);
			
			//获取签名算法
			String sign_algo = jsonob1.get("signature_algorithm").toString();
			
		//获取数字证书的有效期
			Object val = jsonob1.get("validity"); 
			HashMap jsonob2 = JSON.parseObject(val.toString(),HashMap.class);
			String start_time = jsonob2.get("start").toString();
			String end_time = jsonob2.get("end").toString();	
			
	
        //获取颁发者
			Object issuer1 = jsonob1.get("issuer");
			HashMap jsonob3 = JSON.parseObject(issuer1.toString(),HashMap.class);
			String issuer = jsonob3.get("common_name").toString();
			//System.out.println("banfa"+issuer);
		
		//获取拥有者
			Object subject1 = jsonob1.get("subject");
			HashMap jsonob4 = JSON.parseObject(subject1.toString(),HashMap.class);
			String subject = jsonob4.get("common_name").toString();
			   String subje = subject.replaceAll("\\[\"|\"\\]", "");//去掉始端和终端的"["和"]"。 
			 
			   String bt = "https://";
			   StringBuffer sb = new StringBuffer(subje);
			  String newsubje =sb.insert(0,bt).toString();
			   
		//获取签名值
			Object sign = jsonob1.get("signature"); 
			HashMap jsonobtwo = JSON.parseObject(sign.toString(),HashMap.class);
			//Object sign_algo= jsonobtwo.get("signature_algorithm");
			//HashMap jsonobfour = JSON.parseObject(sign_algo.toString(),HashMap.class);
	        String sign2 = jsonobtwo.get("value").toString();
		
	        
	     //获取CRL
	        Object kuozhan = jsonob1.get("extensions");
	      //  System.out.println("kuozhan:"+kuozhan);
	        
	        HashMap kuozhanxiang = JSON.parseObject(kuozhan.toString(),HashMap.class);
	        String crl_url = kuozhanxiang.get("crl_distribution_points").toString();
	        String b = crl_url.replaceAll("\\[\"|\"\\]", "");//去掉始端和终端的"["和"]"。 
	        //System.out.println(crl_url);
	        
	        //获取issuer_urls
	        Object authority_info_access = kuozhanxiang.get("authority_info_access");
	        HashMap json_authority = JSON.parseObject(authority_info_access.toString(),HashMap.class);
	        String issuer_urls = json_authority.get("issuer_urls").toString();
	        String issuer_urls_new = issuer_urls.replaceAll("\\[\"|\"\\]", "");//去掉始端和终端的"["和"]"。
	        //
	        String issurl = issuer_urls_new.replace("http://","https://");
	        
	        Object key_info = jsonob1.get("subject_key_info");
				HashMap jsonob444 = JSON.parseObject(key_info.toString(),HashMap.class);
				String key_algo = jsonob444.get("key_algorithm").toString();
				Object rsa_public_key = jsonob444.get("rsa_public_key");
				HashMap jsonob4444 = JSON.parseObject(rsa_public_key.toString(),HashMap.class);
				//获取公钥的指数
			    String exponent = jsonob4444.get("exponent").toString();
			    //获取公钥的模数
			    String modules = jsonob4444.get("modulus").toString();
			    //生成公钥
			     
			     
			  // !!!!上次断在这里！！！！ -----------------
				//Verify(raw, sign2, modules, exponent);

		        //System.out.println("jiemahou:"+certSN);
			    
			  //结果显示：
			    int j =i+1;
			    bField.append("第i个证书i=="+String.valueOf(j)+ "\n");
			    bField.append("版本："+vers+ "\n");
			    bField.append("序列号:"+serial+ "\n");
			    bField.append("拥有者："+subject+ "\n");
			    bField.append("颁发者:"+issuer+ "\n");
			    bField.append("公钥算法:"+key_algo);
			    bField.append("指数:"+exponent+ "\n");
			    bField.append("模数:"+modules+ "\n");
			    bField.append("签名算法:"+sign_algo+ "\n");
			    bField.append("签名:"+sign2+ "\n");
			    bField.append("CRL:"+b+ "\n");
			    bField.append("-------------"+"\n");
			    bField.append("（一）时间有效性验证"+"\n");
			    bField.append("开始时间:"+start_time + "\n");
			    bField.append("截止时间:"+end_time + "\n");
			
				try {
					if(time_analysis(start_time,end_time)==false){	
						falselist.add(serial);
						notvalitidylist.add(str);
						  bField.append("!!!!时间有效性验证：无效!!!");
						  bField.append("证书有效性验证--无效列表："+falselist);
						
					   }
					   
					   else if(testConnectionTo(newsubje)==false){
						   falselist.add(serial);
						   notvalitidylist.add(str);
						   bField.append("完整性验证：无效!!!");
							  bField.append("证书有效性验证--无效列表："+falselist);
					   }else{
						   
					 

     //  System.out.println("去掉中括号和双引号后的crl_url:"+b);
     
					// BigInteger cer2 = new BigDecimal(serial).toBigInteger().toString(16);
					//System.out.println("cer2:"+cer2);
   
  
					//  String publick = "3082010a02820101008b5e0156b9ec6b";
     //  BigInteger certSN = new BigInteger(publick,16);	        
					 //  System.out.println(certSN);
   // System.out.println("将序列号化成大整数:"+n+"\n");
   
     //System.out.println("issurl:"+issurl);
						   
     
					 
					   
					   

					        BigInteger n = new BigInteger(serial);
					  RSAPublicKey  pubk = getlastpublickey(issurl);					 
                              VerifyCRLSignature(b,n,pubk);
					 if(GetCRL(b,n)==true){
						falselist.add(serial); 
						notvalitidylist.add(str);
						bField.append("证书有效性验证--无效列表："+falselist);
					 }

					   }
				} catch (ParseException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}//时间验证合格的话
		        }
	
	   //写入
	  //  System.out.println(notvalitidylist+"\n");
	   String actual =JSON.toJSONString(notvalitidylist);
	//   System.out.println(actual);
	  //  Gson gson = new Gson();
	   // String jsonStr =gson.toJson(notvalitidylist);
	    try {
	       FileOutputStream fos = new FileOutputStream(new File("c:\\daochu.json"));//这里可以写你想要放的地址
	       Writer writer = new OutputStreamWriter(fos);
	       writer.write(actual);
	       writer.flush();
	       writer.close();
	      } catch (Exception e1) {
	       e1.printStackTrace();
	      }

	     
		

		
	}	
}
 }

