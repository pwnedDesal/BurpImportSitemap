/*
Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Jose Selvi, jose dot selvi at nccgroup dot com

https://github.com/nccgroup/BurpImportSitemap

Released under AGPL see LICENSE for more information
*/

package wstalker.ui;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URISyntaxException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.UUID;

import javax.swing.*;
import javax.xml.parsers.ParserConfigurationException;

import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.awt.Desktop;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IParameter;

import org.xml.sax.SAXException;
import wstalker.WStalker;
import wstalker.imports.WSImport;
import wstalker.imports.WSRequestResponse;

public class WSPanel extends JPanel {

    private final burp.IBurpExtenderCallbacks callbacks;
    private final burp.IExtensionHelpers helpers;
    private final WSImport wsimport;
    private final JCheckBox chkFakeParam;
    private final String paramname = "wstalkerfakeparam";

    // Constructor
    public WSPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = this.callbacks.getHelpers();
        this.wsimport = new WSImport();

        JFileChooser fileChooser = new JFileChooser(){
            @Override
            public void approveSelection(){
                File f = getSelectedFile();
                if(f.exists() && getDialogType() == SAVE_DIALOG){
                    int result = JOptionPane.showConfirmDialog(this,"The file exists, overwrite?","Existing file",JOptionPane.YES_NO_CANCEL_OPTION);
                    switch(result){
                        case JOptionPane.YES_OPTION:
                            super.approveSelection();
                            return;
                        case JOptionPane.NO_OPTION:
                            return;
                        case JOptionPane.CLOSED_OPTION:
                            return;
                        case JOptionPane.CANCEL_OPTION:
                            cancelSelection();
                            return;
                    }
                }
                super.approveSelection();
            }
        };

        // Create the Grid
        GridBagLayout gridBagLayout = new GridBagLayout();
        gridBagLayout.columnWidths = new int[] { 0, 1, 1, 0 };
        gridBagLayout.rowHeights = new int[] { 0, 0, 0, 0, 0, 0, 0 };
        gridBagLayout.columnWeights = new double[] { 0.0, 1.0, 1.0, 0.0, Double.MIN_VALUE };
        gridBagLayout.rowWeights = new double[] { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE };
        this.setLayout(gridBagLayout);

        // Add NCC Logo Image
        // Borrowed from https://github.com/nccgroup/BurpSuiteLoggerPlusPlus/
        ClassLoader cldr = this.getClass().getClassLoader();
        URL imageURLMain = cldr.getResource("AboutMain.png");
        JLabel lblMain = new JLabel("NCC LOGO"); // to see the label in eclipse design tab!
        ImageIcon imageIconMain;
        if (imageURLMain != null) {
            imageIconMain = new ImageIcon(imageURLMain);
            lblMain = new JLabel(imageIconMain);
        }
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = gbc.weighty = 0;
        gbc.gridheight = 9;
        gbc.insets = new Insets(15, 15, 15, 15);
        gbc.gridx = 0;
        gbc.gridy = 0;
        this.add(lblMain, gbc);

        gbc.weightx = 1;
        gbc.anchor = GridBagConstraints.NORTHWEST;

        //
        // FAKE PARAMETER TRICK
        //

        JLabel lblFakeParam = new JLabel("Add fake parameter \"" + this.paramname + "\"");
        gbc.insets = new Insets(20, 0, 5, 5);
        gbc.gridheight = 1;
        gbc.gridx = 1;
        gbc.gridy = 0;
        this.add(lblFakeParam, gbc);

        this.chkFakeParam = new JCheckBox("Enable Fakeparam Trick");
        this.chkFakeParam.setSelected(true); // do the trick by default
        gbc.insets = new Insets(0, 0, 10, 0);
        gbc.gridx = 1;
        gbc.gridy++;
        this.add(chkFakeParam, gbc);

        //
        // NCCGROUP WSTALKER
        //

        JLabel lblImportWStalker = new JLabel("Import WStalker CSV Format");
        gbc.insets = new Insets(20, 0, 5, 5);
        gbc.gridx = 1;
        gbc.gridy++;
        this.add(lblImportWStalker, gbc);

        JButton btnImportWStalker = new JButton("Import WStalker CSV");
        btnImportWStalker.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                ArrayList<IHttpRequestResponse> rs = wsimport.importWStalker();
                sendToSitemap(rs);
            }
        });
        gbc.insets = new Insets(0, 0, 10, 0);
        gbc.gridwidth = 2;
        gbc.gridx = 1;
        gbc.gridy++;
        this.add(btnImportWStalker, gbc);

        //
        // OWASP ZAP
        //

        JLabel lblImportZAP = new JLabel("Import OWASP ZAP Format (\"export messages to file\")");
        gbc.insets = new Insets(20, 0, 5, 5);
        gbc.gridx = 1;
        gbc.gridy++;
        this.add(lblImportZAP, gbc);

        JButton btnImportZAP = new JButton("Import OWASP ZAP");
        btnImportZAP.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                ArrayList<IHttpRequestResponse> rs = wsimport.importZAP();
                sendToSitemap(rs);
            }
        });
        gbc.insets = new Insets(0, 0, 10, 0);
        gbc.gridwidth = 2;
        gbc.gridx = 1;
        gbc.gridy++;
        this.add(btnImportZAP, gbc);

        //
        //import xml SHIT
        //

        JLabel lblImportXML = new JLabel("Import XML file (\"export messages to file\")");
        gbc.insets = new Insets(20, 0, 5, 5);
        gbc.gridx = 1;
        gbc.gridy++;
        this.add(lblImportXML, gbc);

        JButton btnImportXML = new JButton("Import XML file");
        btnImportXML.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                ArrayList<IHttpRequestResponse> rs = null;
                try {
                    rs = wsimport.importXML();
                } catch (ParserConfigurationException parserConfigurationException) {
                    parserConfigurationException.printStackTrace();
                } catch (IOException ioException) {
                    ioException.printStackTrace();
                } catch (SAXException saxException) {
                    saxException.printStackTrace();
                }
                sendToSitemap(rs);
            }
        });
        gbc.insets = new Insets(0, 0, 10, 0);
        gbc.gridwidth = 2;
        gbc.gridx = 1;
        gbc.gridy++;
        this.add(btnImportXML, gbc);

        //
        // Export xml
        //

        JLabel lblExportXML = new JLabel("Export XML Format");
        gbc.insets = new Insets(20, 0, 5, 5);
        gbc.gridx = 1;
        gbc.gridy++;
        this.add(lblExportXML, gbc);

        JButton btnExportXML = new JButton("Export XML Format");
        btnExportXML.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                IHttpRequestResponse[] tmp = callbacks.getSiteMap(null);
                if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION){
                    File outputFile = fileChooser.getSelectedFile();
                    writeStringToFile(createOutputForAppScanStandard(tmp), outputFile);
                }
            }
        });
        gbc.insets = new Insets(0, 0, 10, 0);
        gbc.gridwidth = 2;
        gbc.gridx = 1;
        gbc.gridy++;
        this.add(btnExportXML, gbc);



        //
        // GO TO GITHUB
        //

        JLabel lblGoToGithub = new JLabel("More information.");
        gbc.insets = new Insets(20, 0, 5, 5);
        gbc.gridx = 1;
        gbc.gridy++;
        this.add(lblGoToGithub, gbc);

        JButton btnGoToGithub = new JButton("Open extension homepage");
        btnGoToGithub.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				openWebpage(WStalker.Url);
			}
		});
		gbc.insets = new Insets(0, 0, 10, 0);
		gbc.gridwidth = 2;
		gbc.gridx = 1;
		gbc.gridy++;
        this.add(btnGoToGithub, gbc);
    }
    public void writeStringToFile(String Output, File file){
        BufferedWriter out = null;
        try {
            out = new BufferedWriter(new FileWriter(file));
            out.write(Output);
            JOptionPane.showMessageDialog(null, "File saved successfully.");
        } catch ( IOException e1 ) {
            JOptionPane.showMessageDialog(null, "Error saving file: " + e1.getMessage());
        } finally {
            try {
                out.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }


    public String createOutputForAppScanStandard(IHttpRequestResponse tmp[]){
        callbacks.printOutput("OK, we called CreateOutput: " + tmp.length);
        String Output = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<requests>\n";
        for(int i = 0; i < tmp.length; i++){
            String protocol =  tmp[i].getHttpService().getProtocol();
            String method = helpers.analyzeRequest(tmp[i].getRequest()).getMethod();
            String path = "/";
            String tmpStr = new String(tmp[i].getRequest());
            int firstslash = tmpStr.indexOf(" ");
            int secondslash = tmpStr.indexOf(" ", firstslash + 1);
            int questionmark = tmpStr.indexOf("?", firstslash + 1);
            if(questionmark < secondslash && questionmark > 0){
                secondslash = questionmark;
            }
            path = tmpStr.substring(firstslash + 1, secondslash).replace("\"", "%22");
            int port = tmp[i].getHttpService().getPort();
            String host =  tmp[i].getHttpService().getHost();
            Output += "\t<url method=\"" + method + "\" scheme=\"" + protocol + "\" httpVersion=\"HTTP/1.1\" host=\"" + host + "\"  port=\"" + port + "\" path=\"" + path + "\">" +
                    "<request>" +
                    tmp[i].getRequest() +
                    "</request>" +
                    "<response>" +
                    tmp[i].getResponse() +
                    "</response>" +
                    "</url>\n";
        }
        Output += "</requests>";
        return Output;
    }

    public void sendToSitemap(ArrayList<IHttpRequestResponse> rs) {    
        boolean doTrick = this.chkFakeParam.isSelected();
        this.sendToSitemap(rs, doTrick);
    }

    public void sendToSitemap(ArrayList<IHttpRequestResponse> rs, boolean doTrick) {    

        Iterator<IHttpRequestResponse> i = rs.iterator();
        while (i.hasNext()) {
            IHttpRequestResponse r = i.next();
            this.sendToSitemap(r, doTrick);
        }
    }

    public void sendToSitemap(IHttpRequestResponse r) {    
        boolean doTrick = this.chkFakeParam.isSelected();
        this.sendToSitemap(r, doTrick);
    }

    public void sendToSitemap(IHttpRequestResponse r, boolean doTrick) {
        WSRequestResponse rr = new WSRequestResponse(r);

        // We add the fake parameter if enabled
        if (doTrick) {
            final String uuid = UUID.randomUUID().toString();
            IParameter p = this.helpers.buildParameter(this.paramname, uuid, IParameter.PARAM_URL);

            byte[] b = this.helpers.addParameter(rr.getRequest(), p);
            rr.setRequest(b);
        }

        // Add resulting request/response to SiteMap
        this.callbacks.addToSiteMap(rr);
    }

    // Borrowed from https://github.com/nccgroup/BurpSuiteLoggerPlusPlus/
    private static void openWebpage(URI uri) {
		Desktop desktop = Desktop.isDesktopSupported() ? Desktop.getDesktop() : null;
		if (desktop != null && desktop.isSupported(Desktop.Action.BROWSE)) {
			try {
				desktop.browse(uri);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

    // Borrowed from https://github.com/nccgroup/BurpSuiteLoggerPlusPlus/
	private static void openWebpage(String url) {
		try {
			openWebpage((new URL(url)).toURI());
		} catch (URISyntaxException e) {
			e.printStackTrace();
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
    }
    
    // Requirement
    private static final long serialVersionUID = 5843153017285180474L;
}