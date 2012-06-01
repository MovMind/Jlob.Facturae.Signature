/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package jlob.facturae.signature;

import java.security.*;
import java.util.Enumeration;
import java.security.cert.*;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import java.io.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
/**
 *
 * @author aguadius
 */
public class JLobFacturaeSignature {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
        try
        {
            String path = args[0];
            String serial = args[1];
            X509Certificate cert = GetCert(serial);
            File factura = new java.io.File(path);
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            org.w3c.dom.Document doc = builder.parse(factura);
            es.mityc.facturae.utils.SignatureUtil.sign(doc,cert);
            TransformerFactory tranFactory = TransformerFactory.newInstance();
              Transformer aTransformer = tranFactory.newTransformer();
              Source src = new DOMSource(doc);
              Result dest = new StreamResult(factura);
              aTransformer.transform(src, dest);
        }
        catch(Exception e){
            System.out.println("error" + e.getMessage());
        }
    }
    
    public static X509Certificate GetCert(String serial)
    {
        String serialNumber;
        KeyStore keystore;
        try
        {
            keystore = KeyStore.getInstance("Windows-MY", "SunMSCAPI");
            keystore.load(null, null);
            for(Enumeration oEnum = keystore.aliases();oEnum.hasMoreElements();)
            {
                String alias = (String)oEnum.nextElement();
                X509Certificate oPublicCertificate = (X509Certificate) keystore.getCertificate(alias);                        
                PrivateKey oPrivateKey = (PrivateKey) keystore.getKey(alias,null);
                if(oPrivateKey==null)continue;
                serialNumber = oPublicCertificate.getSerialNumber().toString();
                if(serial.equals(serialNumber))
                {
                    return oPublicCertificate;
                }
                System.out.println(oPublicCertificate.getSerialNumber());
            }
        }catch(Exception e)
        {
        
        }
        return null;
    }
    
}
