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

        getSupportActionBar().setTitle("Connecting to " + serverIpAddress + ":" + sendPort + " ...");

        if (!serverIpAddress.equals("")) {
            s = new Server(mMessageAdapter, mMessageRecycler, messageArray, myport, serverIpAddress);
            s.start();
        }

        try {
            crypt = new Crypt();
            System.out.println("Crypt init done");
            System.out.println("RSA public  key: " + crypt.sRSApublicKey);
            System.out.println("Session     key: " + crypt.getSessionKey());
        } catch (Exception e) {
            e.printStackTrace();
        }

        Client client = new Client("0:" + crypt.sRSApublicKey);
        client.execute();

        sent.setOnClickListener(v -> {
            if (!smessage.getText().toString().isEmpty()) {
                Client client1;
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
        String message;
        String sendString = "";

        Client(String message) {
            this.message = message;
        }

        @Override
        protected String doInBackground(Void... voids) {
            try {
                if (message.startsWith("3:")) {
                    //msg = crypt.encrypt(msg.substring(2));
                    Log.i(cTAG, "Encrypted string: " + message);
                    sendString = "3:" + crypt.KUZencrypt(message.substring(2)) + " ";
                } else {
                    sendString = message;
                }

                String IP = serverIpAddress;
                int port = sendPort;
                Socket clientSocket = new Socket(IP, port);
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
            return message;
        }

        @Override
        protected void onPostExecute(String result) {
            runOnUiThread(() -> sent.setEnabled(true));
            Log.i(cTAG, "on post execution result => " + result);

            if (result.startsWith("3:")) {
                result = result.substring(2);
                String[] sArray = result.split("::sig::");

                messageArray.add(new Message(sArray[0], 0, Calendar.getInstance().getTime()));
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
                    return null;
                }

                if (text != null && text.length() > 2) {
                    if (text.startsWith("0:"))
                    {
                        text = text.substring(2, text.length() - 1);
                        Log.i(sTAG, "1. get RCA public key (" + text.length() + "): " + text);

                        try {
                            crypt.sRSApublicKey = text;
                            Log.i(sTAG, "New RSA public key: " + crypt.sRSApublicKey);
                            Log.i(sTAG, "Session key: " + crypt.getSessionKey());
                            Log.i(sTAG, "Encrypted session key: " + crypt.RSAencryptWithPublic(crypt.sRSApublicKey, crypt.getSessionKey()));
                            //Client cl = new Client("1:" + crypt.encryptByPublicRSA(crypt.sRSApublicKey, crypt.sessionKey));
                            //cl.execute();

                            return String.format("1:%s", crypt.RSAencryptWithPublic(crypt.sRSApublicKey, crypt.getSessionKey()));

                        } catch (Exception e) {
                            e.printStackTrace();
                            return null;
                        }
                    }
                    if (text.startsWith("1:"))
                    {
                        Log.i(sTAG, "2. get encrypted session key (" + text.length() + "): " + text);
                        System.out.println("Encrypted session key: " + text);
                        text = text.substring(2, text.length() - 1);

                        try {
                            crypt.setSessionKey(text);
                            System.out.println("New session key: " + crypt.getSessionKey());
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        //Client cl = new Client("2: Done");
                        //cl.execute();
                        return "2: Done";
                    }
                    if (text.startsWith("2:"))
                    {
                        if (!isSession) {
                            isSession = true;
                            Log.i(sTAG, "3. Session established");

                            //Client cl = new Client("2: Done");
                            //cl.execute();
                            return "2: Done";
                        }
                    }
                    if (text.startsWith("3:")) {

                        Log.i(sTAG, "3. get message (" + text.length() + "): " + text);

                        StringBuilder stringBuilder = new StringBuilder(text);
                        text = stringBuilder.substring(2, text.length() - 2);
                        try {
                            Log.i(sTAG, "Try decr: " + text);
                            Log.i(sTAG, "Session key: " + crypt.getSessionKey());
                            text = crypt.KUZdecrypt(text);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }

                        return "3:" + text;

                        //String[] sArray = text.split("::sig::");
                        //if (!crypt.checkSig(sArray[0], sArray[1])) {
                        //    getSupportActionBar().setTitle("Wrong signature received!");
                        //    Toast.makeText(getApplicationContext(), "Wrong signature received!", Toast.LENGTH_LONG).show();
                        //}
                        //messageArray.add(new Message(sArray[0], 1, Calendar.getInstance().getTime()));
                        //messageList.setAdapter(mAdapter);
                    }
                }
                else {System.out.println("Get null string");}
                return null;
            }

            protected void onPostExecute(String text) {
                Log.d(sTAG, "onPostExecute: Result " + text);
                Client cl;

                if (text != null) {
                    if (text.startsWith("0:")) {
                        cl = new Client(text);
                        cl.execute();
                    }
                    if (text.startsWith("1:")) {
                        cl = new Client(text);
                        cl.execute();
                    }
                    if (text.startsWith("2:")) {
                        getSupportActionBar().setTitle("Connected to " + serverIP + ":" + sendPort);
                        cl = new Client(text);
                        cl.execute();
                    }
                    if (text.startsWith("3:")) {
                        text = text.substring(2);
                        String[] sArray = text.split("::sig::");

                        if (!crypt.checkSig(sArray[0], sArray[1])) {
                            getSupportActionBar().setTitle("Wrong signature received!");
                            Toast.makeText(getApplicationContext(), "Wrong signature received!", Toast.LENGTH_LONG).show();
                        }

                        messageArray.add(new Message(sArray[0], 1, Calendar.getInstance().getTime()));
                        messageList.setAdapter(mAdapter);
                    }
                }
            }
        }
    }
}