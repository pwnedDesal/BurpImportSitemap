/*
Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Jose Selvi, jose dot selvi at nccgroup dot com

https://github.com/nccgroup/BurpImportSitemap

Released under AGPL see LICENSE for more information
*/

package wstalker.imports;

import java.io.*;
import java.net.URL;
import javax.swing.JFileChooser;
import java.util.ArrayList;
import java.util.Iterator;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;

import org.xml.sax.SAXException;
import wstalker.WStalker;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.w3c.dom.Node;
import org.w3c.dom.Element;
public class WSImport {

    public static String getLoadFile() {
        JFileChooser chooser = null;
        chooser = new JFileChooser();
        chooser.setDialogTitle("Import File");
        int val = chooser.showOpenDialog(null);

        if (val == JFileChooser.APPROVE_OPTION) {
            return chooser.getSelectedFile().getAbsolutePath();
        }

        return "";
    }

    public static ArrayList<String> readFile(String filename) {
        BufferedReader reader;
        ArrayList<String> lines = new ArrayList<String>();

        try {
            reader = new BufferedReader(new FileReader(filename));
        } catch (FileNotFoundException e) {
            return new ArrayList<String>();
        }
        try {
            String line;
            while ( (line = reader.readLine()) != null ) {
                lines.add(line);
            }
        } catch (IOException e) {
            return new ArrayList<String>();
        }

        return lines;
    }

    public static ArrayList<IHttpRequestResponse> importWStalker() {
        ArrayList<String> lines = new ArrayList<String>();
        ArrayList<IHttpRequestResponse> requests = new ArrayList<IHttpRequestResponse>();
        IExtensionHelpers helpers = WStalker.callbacks.getHelpers();
        
        String filename = getLoadFile();
        if ( filename.length() == 0 ) { // exit if no file selected
            return new ArrayList<IHttpRequestResponse>();
        }

        lines = readFile(filename);//read the file. ang gawin dito read db TODO:
        Iterator<String> i = lines.iterator();
        
        while (i.hasNext()) {
            try {
                String line = i.next();
                String[] v = line.split(","); // Format: "base64(request),base64(response),url"

                byte[] request = helpers.base64Decode(v[0]);
                byte[] response = helpers.base64Decode(v[1]);
                String url = v[3];

                WSRequestResponse x = new WSRequestResponse(url, request, response);
                requests.add(x);

            } catch (Exception e) {
                return new ArrayList<IHttpRequestResponse>();
            }
        }

        return requests;
    }
    public static ArrayList<IHttpRequestResponse> importXML() throws ParserConfigurationException, IOException, SAXException {
        ArrayList<String> lines = new ArrayList<String>();
        ArrayList<IHttpRequestResponse> requests = new ArrayList<IHttpRequestResponse>();
        IExtensionHelpers helpers = WStalker.callbacks.getHelpers();

        String filename = getLoadFile();
        PrintWriter stdout = new PrintWriter(WStalker.callbacks.getStdout(), true);
        stdout.println(filename);

        //reading xml file
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.parse(filename);
        doc.getDocumentElement().normalize();
        stdout.println("Root element :" + doc.getDocumentElement().getNodeName()); //should `request`
        NodeList nList = doc.getElementsByTagName("url");

        if ( filename.length() == 0 ) { // exit if no file selected
            return new ArrayList<IHttpRequestResponse>();
        }
        for (int temp = 0; temp < nList.getLength(); temp++) {
            Node nNode = nList.item(temp);
            System.out.println("\nCurrent Element :" + nNode.getNodeName());
            if (nNode.getNodeType() == Node.ELEMENT_NODE) {
                Element eElement = (Element) nNode;
                String url=eElement.getAttribute("scheme") + "://" + eElement.getAttribute("host") + ":" +
                        eElement.getAttribute("port") + eElement.getAttribute("path");
                byte[] request=helpers.base64Decode(eElement.getElementsByTagName("request").item(0).getTextContent());
                byte[] response=helpers.base64Decode(eElement.getElementsByTagName("response").item(0).getTextContent());
                WSRequestResponse x = new WSRequestResponse(url, request, response);
                requests.add(x);
            }
        }

        return requests;
    }

    public static ArrayList<IHttpRequestResponse> importZAP() {
        ArrayList<String> lines = new ArrayList<String>();
        ArrayList<IHttpRequestResponse> requests = new ArrayList<IHttpRequestResponse>();
        IExtensionHelpers helpers = WStalker.callbacks.getHelpers();
        
        String filename = getLoadFile();
        if ( filename.length() == 0 ) { // exit if no file selected
            return new ArrayList<IHttpRequestResponse>();
        }

        lines = readFile(filename);// change this to read xml file then create a iterator as well

        Iterator<String> i = lines.iterator();

        // Format:
        // ==== [0-9]+ ==========
        // REQUEST
        // <empty>
        // RESPONSE
        String reSeparator = "^==== [0-9]+ ==========$";
        String reResponse = "^HTTP/[0-9]\\.[0-9] [0-9]+ .*$";

        // Ignore first line, since it should be a separator
        if ( i.hasNext() ) {
            i.next();
        }

        boolean isRequest = true;
        String requestBuffer = "";
        String responseBuffer = "";
        String url = "";

        // Loop lines
        while (i.hasNext()) {
            String line = i.next();

            // Request and Response Ready
            if ( line.matches(reSeparator) || !i.hasNext() ) {
                // TODO: Remove one or two \n at the end of requestBuffer

                byte[] req = helpers.stringToBytes(requestBuffer);
                byte[] res = helpers.stringToBytes(responseBuffer);

                // Add IHttpRequestResponse Object
                WSRequestResponse x = new WSRequestResponse(url, req, res);
                requests.add(x);//add new urls to the request array
                WStalker.callbacks.issueAlert(requestBuffer);

                // Reset content
                isRequest = true;
                requestBuffer = "";
                responseBuffer = "";
                url = "";

                continue;
            }

            // It's the beginning of a request
            if ( requestBuffer.length() == 0 ) {
                try {
                    // Expected format: "GET https://whatever/whatever.html HTTP/1.1"
                    String[] x = line.split(" ");
                    url = x[1];

                    URL u = new URL(url);
                    String path = u.getPath();
                    line = x[0] + " " + path + " " + x[2]; // fix the path in the request

                } catch (Exception e) {
                    return new ArrayList<IHttpRequestResponse>();
                } 
            }

            // It's the beginning of a response
            if ( line.matches(reResponse) ) {
                isRequest = false;
            }

            // Add line to the corresponding buffer
            if ( isRequest ) {
                requestBuffer += line;
                requestBuffer += "\n";
            } else {
                responseBuffer += line;
                responseBuffer += "\n";
            }
        }

        return requests;
    }

    public static boolean loadImported(ArrayList<IHttpRequestResponse> requests) {
        
        return true;
    }
}