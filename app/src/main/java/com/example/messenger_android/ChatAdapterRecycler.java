package com.example.messenger_android;

import android.annotation.SuppressLint;
import android.content.Context;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.Animation;
import android.view.animation.AnimationUtils;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import java.text.SimpleDateFormat;
import java.util.ArrayList;

import static android.content.ContentValues.TAG;

public class ChatAdapterRecycler extends RecyclerView.Adapter {
    private static final int VIEW_TYPE_MESSAGE_SENT = 1;
    private static final int VIEW_TYPE_MESSAGE_RECEIVED = 2;
    private static final int LATEST_TYPE_MESSAGE_SENT = 3;
    private static final int LATEST_TYPE_MESSAGE_RECEIVED = 4;
    private final Context context;
    private final ArrayList<Message> arrayList;
    ChatAdapterRecycler(Context context, ArrayList<Message> arrayList) {
        this.context = context;
        this.arrayList = arrayList;
    }

    @Override
    public int getItemViewType(int position) {
        Message message = arrayList.get(position);

        if (message.isSent() && position != arrayList.size() - 1)
            return VIEW_TYPE_MESSAGE_SENT;
        else if (!message.isSent() && position != arrayList.size() - 1)
            return VIEW_TYPE_MESSAGE_RECEIVED;
        else if (message.isSent() && position == arrayList.size() - 1)
            return LATEST_TYPE_MESSAGE_SENT;
        else if (!message.isSent() && position == arrayList.size() - 1)
            return LATEST_TYPE_MESSAGE_RECEIVED;
        return 0;
    }

    @NonNull
    @Override
    public RecyclerView.ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view;
        Animation animation = AnimationUtils.loadAnimation(context, R.anim.slide_from_bottom);

        if (viewType == VIEW_TYPE_MESSAGE_SENT) {
            view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_message_sent, parent, false);
            return new SentMessageHolder(view);
        } else if (viewType == VIEW_TYPE_MESSAGE_RECEIVED) {
            view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_message_received, parent, false);
            return new ReceivedMessageHolder(view);
        } else if (viewType == LATEST_TYPE_MESSAGE_SENT) {
            view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_message_sent, parent, false);
            view.startAnimation(animation);
            return new SentMessageHolder(view);
        } else if (viewType == LATEST_TYPE_MESSAGE_RECEIVED) {
            view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_message_received, parent, false);
            view.startAnimation(animation);
            return new ReceivedMessageHolder(view);
        }
        return null;
    }

    @Override
    public void onBindViewHolder(@NonNull RecyclerView.ViewHolder holder, int position) {
        Message message = arrayList.get(position);
        switch (holder.getItemViewType()) {
            case VIEW_TYPE_MESSAGE_SENT:
            case LATEST_TYPE_MESSAGE_SENT:
                ((SentMessageHolder) holder).bind(message);
                break;
            case VIEW_TYPE_MESSAGE_RECEIVED:
            case LATEST_TYPE_MESSAGE_RECEIVED:
                ((ReceivedMessageHolder) holder).bind(message);
                break;
        }
    }

    @Override
    public int getItemCount() {
        return arrayList.size();
    }

    private static class ReceivedMessageHolder extends RecyclerView.ViewHolder {
        TextView messageText, timeText;

        ReceivedMessageHolder(View itemView) {
            super(itemView);
            messageText = itemView.findViewById(R.id.text_message_body);
            timeText = itemView.findViewById(R.id.text_message_time);
        }


        void bind(Message message) {
            @SuppressLint("SimpleDateFormat") SimpleDateFormat sdf = new SimpleDateFormat("HH:mm");
            String currentDateTimeString = sdf.format(message.getTime());

            messageText.setText(message.getMessage());
            timeText.setText(currentDateTimeString);
            Log.d(TAG, "bind: " + message.getMessage());
        }
    }

    private static class SentMessageHolder extends RecyclerView.ViewHolder {
        TextView messageText, timeText;

        SentMessageHolder(View itemView) {
            super(itemView);
            messageText = itemView.findViewById(R.id.send_message_body);
            timeText = itemView.findViewById(R.id.text_message_time);
        }

        void bind(Message message) {
            String newMessage = message.getMessage();
            @SuppressLint("SimpleDateFormat") SimpleDateFormat sdf = new SimpleDateFormat("HH:mm");
            String currentDateTimeString = sdf.format(message.getTime());

            messageText.setText(newMessage);
            timeText.setText(currentDateTimeString);
        }
    }
}
