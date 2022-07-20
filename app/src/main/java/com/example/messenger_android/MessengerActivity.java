package com.example.messenger_android;

import android.annotation.SuppressLint;
import android.content.Intent;
import android.net.wifi.WifiManager;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Handler;
import android.text.format.Formatter;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Calendar;


public class MessengerActivity extends AppCompatActivity{
    String cTAG = "CLIENT";
    String sTAG = "SERVER";

    EditText smessage;
    Button sent;
    String serverIpAddress = "";
    int myport;
    int sendPort;
    ArrayList<Message> messageArray;
    Server s;
    String ownIp;
    Boolean isSession = false;

    private Boolean exit = false;
    private RecyclerView mMessageRecycler;
    private ChatAdapterRecycler mMessageAdapter;

    Crypt crypt;

    @SuppressLint("CutPasteId")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_chatbox);

        smessage = findViewById(R.id.editTextChatbox);
        sent = findViewById(R.id.sendButton);

        messageArray = new ArrayList<>();
        mMessageRecycler = findViewById(R.id.message_list);
        mMessageAdapter = new ChatAdapterRecycler(this, messageArray);
        LinearLayoutManager layoutManager = new LinearLayoutManager(this);
        layoutManager.setOrientation(LinearLayoutManager.VERTICAL);
        layoutManager.setStackFromEnd(true);
        layoutManager.setSmoothScrollbarEnabled(true);

        mMessageRecycler.setLayoutManager(layoutManager);

        Bundle bundle = getIntent().getExtras();
        if (bundle != null) {
            String info = bundle.getString("ip&port");
            assert info != null;
            String[] messengerInfo = info.split(" ");
            myport = Integer.parseInt(messengerInfo[0]);
            serverIpAddress = messengerInfo[1];
            sendPort = Integer.parseInt(messengerInfo[2]);
        }
        WifiManager wm = (WifiManager) getApplicationContext().getSystemService(WIFI_SERVICE);
        ownIp = Formatter.formatIpAddress(wm.getConnectionInfo().getIpAddress());

        getSupportActionBar().setTitle("Connecting to " + serverIpAddress + ":" + sendPort);

        if (!serverIpAddress.equals("")) {
            s = new Server(mMessageAdapter, mMessageRecycler, messageArray, myport, serverIpAddress);
            s.start();
        }

        try {
            crypt = new Crypt();
            System.out.println("Crypt init done");
            System.out.println("RSA public key: " + crypt.RSApublicKey);
            System.out.println("RSA public key: " + crypt.sRSApublicKey);
            System.out.println("Session key:    " + crypt.sessionKey);
        } catch (Exception e) {
            e.printStackTrace();
        }

        Client client = new Client("0:" + crypt.sRSApublicKey);
        client.execute();

        sent.setOnClickListener(v -> {
            if (!smessage.getText().toString().isEmpty()) {
                Client client1 = null;
                try {
                    System.out.println("Original string:  3:" + smessage.getText().toString() + "::sig::" + crypt.sigData(smessage.getText().toString()));
                    System.out.println("Encrypted string: 3:" + crypt.KUZencrypt(smessage.getText().toString() + "::sig::" + crypt.sigData(smessage.getText().toString())));
                    client1 = new Client("3:" + smessage.getText().toString() + "::sig::" + crypt.sigData(smessage.getText().toString()));
                    client1.execute();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
    }

    @Override
    public void onBackPressed() {
        if (exit) {
            s.interrupt();
            finish();
        } else {
            Toast.makeText(this, "Press Back again to Exit.",
                    Toast.LENGTH_SHORT).show();
            exit = true;
            new Handler().postDelayed(() -> exit = false, 3 * 1000);
        }
    }

    @SuppressLint("StaticFieldLeak")
    public class Client extends AsyncTask<Void, Void, String> {
        String msg;
        String sendString = "";

        Client(String message) {
            msg = message;
        }

        @Override
        protected String doInBackground(Void... voids) {
            try {
                if (msg.startsWith("3:")) {
                    //msg = crypt.encrypt(msg.substring(2));
                    Log.i(cTAG, "Encrypted string: " + msg);
                    sendString = "3:" + crypt.KUZencrypt(msg.substring(2)) + " ";
                } else {
                    sendString = msg;
                }

                String ipadd = serverIpAddress;
                int portr = sendPort;
                Socket clientSocket = new Socket(ipadd, portr);
                OutputStream outToServer = clientSocket.getOutputStream();
                PrintWriter output = new PrintWriter(outToServer);
                output.println(sendString);
                output.flush();

                outToServer.close();
                output.close();
                clientSocket.close();
                runOnUiThread(() -> sent.setEnabled(false));
            } catch (Exception e) {
                e.printStackTrace();
            }
            Log.i(cTAG, "Trying to send (" + sendString.length() + "): " + sendString);
            return msg;
        }

        @Override
        protected void onPostExecute(String result) {
            runOnUiThread(() -> sent.setEnabled(true));
            Log.i(cTAG, "on post execution result => " + msg);
            StringBuilder stringBuilder = new StringBuilder(result);
            if (stringBuilder.charAt(0) == '3' && stringBuilder.charAt(1) == ':') {
                stringBuilder.deleteCharAt(0);
                stringBuilder.deleteCharAt(0);
                msg = stringBuilder.toString();

                String[] sArray = msg.split("::sig::");

                messageArray.add(new Message(sArray[0], 0, Calendar.getInstance().getTime()));
                //messageArray.add(new Message(sArray[0], 0, Calendar.getInstance().getTime()));
                mMessageRecycler.setAdapter(mMessageAdapter);
                smessage.setText("");
            }
        }
    }

    class Server extends Thread {
        private final String serverIP;
        private final int serverPort;

        private final RecyclerView messageList;
        private final ArrayList<Message> messageArray;
        private final ChatAdapterRecycler mAdapter;

        Server(ChatAdapterRecycler mAdapter,
               RecyclerView messageList, ArrayList<Message> messageArray, int serverPort, String serverIP) {
            this.messageArray = messageArray;
            this.messageList = messageList;
            this.mAdapter = mAdapter;
            this.serverPort = serverPort;
            this.serverIP = serverIP;
        }

        @SuppressLint("SetTextI18n")
        public void run() {
            try {
                ServerSocket initSocket = new ServerSocket(serverPort);
                initSocket.setReuseAddress(true);
                System.out.println(sTAG + "started");
                while (!Thread.interrupted()) {
                    Socket connectSocket = initSocket.accept();
                    receiveMessages handle = new receiveMessages();
                    handle.execute(connectSocket);
                }
                initSocket.close();
            } catch (IOException e) {
                Toast.makeText(getApplicationContext(), "Server Socket initialization failed.", Toast.LENGTH_SHORT).show();
                Log.i(sTAG, "Server Socket initialization failed.");
                e.printStackTrace();
            }
        }

        @SuppressLint("StaticFieldLeak")
        public class receiveMessages extends AsyncTask<Socket, Void, String> {
            String text = "";
            @Override
            protected String doInBackground(Socket... sockets) {
                try {
                    byte[] content = new byte[1024];

                    InputStream inputStream = sockets[0].getInputStream();
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();

                    int bytesRead = 0;
                    while(bytesRead != -1) {
                        bytesRead = inputStream.read(content);
                        if (bytesRead != -1) {baos.write( content, 0, bytesRead );}
                    }
                    System.out.println(bytesRead + " " + baos.size() + ": " + baos);
                    text = baos.toString();
                    inputStream.close();
                    baos.flush();
                    Log.i(sTAG, "Received: " + text);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                return text;
            }

            protected void onPostExecute(String result) {
                Log.d(sTAG, "onPostExecute: Result " + result);
                if (result != null && result.length() > 2) {
                    if (result.charAt(0) == '0' && result.charAt(1) == ':')
                    {
                        result = result.substring(2, result.length() - 1);
                        Log.i(sTAG, "1. get RCA public key (" + result.length() + "): " + result);

                        try {
                            crypt.sRSApublicKey = result;
                            Log.i(sTAG, "New RSA public key: " + crypt.sRSApublicKey);
                            Log.i(sTAG, "Session key: " + crypt.sessionKey);
                            Log.i(sTAG, "Encrypted session key: " + crypt.encryptByPublicRSA(crypt.sRSApublicKey, crypt.sessionKey));
                            Client cl = new Client("1:" + crypt.encryptByPublicRSA(crypt.sRSApublicKey, crypt.sessionKey));
                            cl.execute();

                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                    if (result.charAt(0) == '1' && result.charAt(1) == ':')
                    {
                        Log.i(sTAG, "2. get encrypted session key (" + result.length() + "): " + result);
                        System.out.println("Encrypted session key: " + result);
                        StringBuilder stringBuilder = new StringBuilder(result);
                        stringBuilder.deleteCharAt(result.length() - 1);
                        stringBuilder.deleteCharAt(0);
                        stringBuilder.deleteCharAt(0);
                        result = stringBuilder.toString();
                        try {
                            crypt.setSessionKey(result);
                            System.out.println("New session key: " + crypt.sessionKey);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        Client cl = new Client("2: Done");
                        cl.execute();
                    }
                    if (result.charAt(0) == '2' && result.charAt(1) == ':')
                    {
                        if (!isSession) {
                            isSession = true;
                            Log.i(sTAG, "3. Session established");
                            getSupportActionBar().setTitle("Connected to " + serverIP + ":" + sendPort);

                            Client cl = new Client("2: Done");
                            cl.execute();
                        }
                    }
                    if (result.charAt(0) == '3' && result.charAt(1) == ':') {

                        Log.i(sTAG, "3. get message (" + result.length() + "): " + result);

                        StringBuilder stringBuilder = new StringBuilder(result);
                        result = stringBuilder.substring(2, result.length() - 2);
                        try {
                            Log.i(sTAG, "Try decr: " + result);
                            Log.i(sTAG, "Session key: " + crypt.sessionKey);
                            result = crypt.KUZdecrypt(result);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }

                        String[] sArray = result.split("::sig::");

                        if (!crypt.checkSig(sArray[0], sArray[1])) {
                            getSupportActionBar().setTitle("Wrong signature received!");
                            Toast.makeText(getApplicationContext(), "Wrong signature received!", Toast.LENGTH_LONG).show();
                        }

                        messageArray.add(new Message(sArray[0], 1, Calendar.getInstance().getTime()));
                        messageList.setAdapter(mAdapter);
                    }
                }
                else {
                    System.out.println("Get null string");
                }
            }
        }
    }
}