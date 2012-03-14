/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package com.android.tools.sdkcontroller.lib;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.nio.channels.spi.*;
import java.net.*;
import java.util.*;
import android.util.Log;

/**
 * Encapsulates a connection with the emulator. The connection is established
 * over a TCP port forwarding enabled with 'adb forward' command.
 *
 * Communication with the emulator is performed via two socket channels connected
 * to the forwarded TCP port. One channel is a query channel that is intended
 * solely for receiving queries from the emulator. Another channel is an event
 * channel that is intended for sending notification messages (events) to the
 * emulator.
 *
 * Emulator is considered to be "connected" when both channels are connected.
 * Emulator is considered to be "disconnected" when connection with any of the
 * channels is lost.
 *
 * Instance of this class is operational only for a single connection with the
 * emulator. Once connection is established and then lost, a new instance of this
 * class must be created to establish new connection.
 *
 * Note that connection with the device over TCP port forwarding is extremely
 * fragile at the moment. For whatever reason the connection is even more fragile
 * if device uses asynchronous sockets (based on java.nio API). So, to address
 * this issue Emulator class implements two types of connections. One is using
 * synchronous sockets, and another is using asynchronous sockets. The type of
 * connection is selected when Emulator instance is created (see comments to
 * Emulator's constructor).
 *
 * According to the exchange protocol with the emulator, queries, responses to
 * the queries, and notification messages are all zero-terminated strings.
 */
public class Emulator {
    /** Defines connection types supported by the Emulator class. */
    public enum EmulatorConnectionType {
        /** Use asynchronous connection (based on java.nio API). */
        ASYNC_CONNECTION,
        /** Use synchronous connection (based on synchronous Socket objects). */
        SYNC_CONNECTION,
    }

    /** TCP port reserved for the sensors emulation. */
    public static final int SENSORS_PORT = 1968;
    /** TCP port reserved for the multitouch emulation. */
    public static final int MULTITOUCH_PORT = 1969;
    /** Tag for logging messages. */
    private static final String TAG = "Emulator";
    /** Emulator events listener. */
    private OnEmulatorListener mListener;
    /** I/O selector (looper). */
    private Selector mSelector;
    /** Server socket channel. */
    private ServerSocketChannel mServerSocket;
    /** Query channel. */
    private EmulatorChannel mQueryChannel;
    /** Event channel. */
    private EmulatorChannel mEventChannel;
    /** Selector for the connection type. */
    private EmulatorConnectionType mConnectionType;
    /** Connection status */
    private boolean mIsConnected = false;
    /** Disconnection status */
    private boolean mIsDisconnected = false;

    /***************************************************************************
     * EmulatorChannel - Base class for sync / async channels.
     **************************************************************************/

    /**
     * Encapsulates a base class for synchronous and asynchronous communication
     * channels.
     */
    private abstract class EmulatorChannel {
        /** Identifier for a query channel type. */
        private static final String QUERY_CHANNEL = "query";
        /** Identifier for an event channel type. */
        private static final String EVENT_CHANNEL = "event";

        /***********************************************************************
         * Abstract API
         **********************************************************************/

        /**
         * Sends a message via this channel.
         *
         * @param msg Zero-terminated message string to send.
         */
        public abstract void sendMessage(String msg) throws IOException;

        /**
         * Closes this channel.
         */
        abstract public void closeChannel() throws IOException;

        /***********************************************************************
         * Public API
         **********************************************************************/

        /**
         * Constructs EmulatorChannel instance.
         */
        public EmulatorChannel() {
        }

        /**
         * Handles a query received in this channel.
         *
         * @param query_str Query received from this channel. All queries are
         *            formatted as such: <query>:<query parameters> where -
         *            <query> Is a query name that identifies the query, and -
         *            <query parameters> represent parameters for the query.
         *            Query name and query parameters are separated with a ':'
         *            character.
         */
        public void onQueryReceived(String query_str) throws IOException {
            String query, query_param;

            // Lets see if query has parameters.
            int sep = query_str.indexOf(':');
            if (sep == -1) {
                // Query has no parameters.
                query = query_str;
                query_param = "";
            } else {
                // Separate query name from its parameters.
                query = query_str.substring(0, sep);
                // Make sure that substring after the ':' does contain
                // something, otherwise the query is paramless.
                query_param = (sep < (query_str.length() - 1)) ? query_str.substring(sep + 1) : "";
            }

            // Handle the query, obtain response string, and reply it back to
            // the emulator.
            String response = onQuery(query, query_param);
            if (response.length() == 0) {
                Logw("No response to query '" + query + "'. Replying with 'ko'");
                response = "ko:Protocol error.\0";
            } else if (response.charAt(response.length() - 1) != '\0') {
                Logw("Response '" + response + "' to query '" + query
                        + "' does not contain zero-terminator.");
            }
            sendMessage(response);
        }
    } // EmulatorChannel

    /***************************************************************************
     * EmulatorSyncChannel - Implements a synchronous channel.
     **************************************************************************/

    /**
     * Encapsulates a synchronous communication channel with the emulator.
     */
    private class EmulatorSyncChannel extends EmulatorChannel {
        /** Communication socket. */
        private Socket mSocket;

        /**
         * Constructs EmulatorSyncChannel instance.
         *
         * @param socket Connected ('accept'ed) communication socket.
         */
        public EmulatorSyncChannel(Socket socket) {
            mSocket = socket;
            // Start the reader thread.
            new Thread(new Runnable() {
                @Override
                public void run() {
                    theReader();
                }
            }).start();
        }

        /***********************************************************************
         * Abstract API implementation
         **********************************************************************/

        /**
         * Sends a message via this channel.
         *
         * @param msg Zero-terminated message string to send.
         */
        @Override
        public void sendMessage(String msg) throws IOException {
            if (msg.charAt(msg.length() - 1) != '\0') {
                Logw("Missing zero-terminator in message '" + msg + "'");
            }
            mSocket.getOutputStream().write(msg.getBytes());
        }

        /**
         * Closes this channel.
         */
        @Override
        public void closeChannel() throws IOException {
            mSocket.close();
        }

        /***********************************************************************
         * EmulatorSyncChannel implementation
         **********************************************************************/

        /**
         * The reader thread: loops reading and dispatching queries.
         */
        private void theReader() {
            try {
                for (;;) {
                    String query = readSocketString(mSocket);
                    onQueryReceived(query);
                }
            } catch (IOException e) {
                onLostConnection();
            }
        }
    } // EmulatorSyncChannel

    /***************************************************************************
     * EmulatorAsyncChannel - Implements an asynchronous channel.
     **************************************************************************/

    /**
     * Encapsulates an asynchronous communication channel with the emulator.
     */
    private class EmulatorAsyncChannel extends EmulatorChannel {
        /** Communication socket channel. */
        private SocketChannel mChannel;
        /** I/O selection key for this channel. */
        private SelectionKey mSelectionKey;
        /** Accumulator for the query string received in this channel. */
        private String mQuery = "";
        /**
         * Preallocated character reader that is used when data is read from
         * this channel. See 'onRead' method for more details.
         */
        private ByteBuffer mIn = ByteBuffer.allocate(1);
        /**
         * Currently sent notification message(s). See 'sendMessage', and
         * 'onWrite' methods for more details.
         */
        private ByteBuffer mOut;
        /**
         * Array of pending notification messages. See 'sendMessage', and
         * 'onWrite' methods for more details.
         */
        private Vector<String> mNotifications = new Vector<String>();

        /**
         * Constructs EmulatorAsyncChannel instance.
         *
         * @param channel Accepted socket channel to use for communication.
         * @throws IOException
         */
        private EmulatorAsyncChannel(SocketChannel channel) throws IOException {
            // Mark character reader at the beginning, so we can reset it after
            // next read character has been pulled out from the buffer.
            mIn.mark();

            // Configure communication channel as non-blocking, and register
            // it with the I/O selector for reading.
            mChannel = channel;
            mChannel.configureBlocking(false);
            mSelectionKey = mChannel.register(mSelector, SelectionKey.OP_READ, this);
            // Start receiving read I/O.
            mSelectionKey.selector().wakeup();
        }

        /***********************************************************************
         * Abstract API implementation
         **********************************************************************/

        /**
         * Sends a message via this channel.
         *
         * @param msg Zero-terminated message string to send.
         */
        @Override
        public void sendMessage(String msg) throws IOException {
            if (msg.charAt(msg.length() - 1) != '\0') {
                Logw("Missing zero-terminator in message '" + msg + "'");
            }
            synchronized (this) {
                if (mOut != null) {
                    // Channel is busy with writing another message.
                    // Queue this one. It will be picked up later when current
                    // write operation is completed.
                    mNotifications.add(msg);
                    return;
                }

                // No other messages are in progress. Send this one outside of
                // the lock.
                mOut = ByteBuffer.wrap(msg.getBytes());
            }
            mChannel.write(mOut);

            // Lets see if we were able to send the entire message.
            if (mOut.hasRemaining()) {
                // Write didn't complete. Schedule write I/O callback to
                // pick up from where this write has left.
                enableWrite();
                return;
            }

            // Entire message has been sent. Lets see if other messages were
            // queued while we were busy sending this one.
            for (;;) {
                synchronized (this) {
                    // Dequeue message that was yielding to this write.
                    if (!dequeueMessage()) {
                        // Writing is over...
                        disableWrite();
                        mOut = null;
                        return;
                    }
                }

                // Send queued message.
                mChannel.write(mOut);

                // Lets see if we were able to send the entire message.
                if (mOut.hasRemaining()) {
                    // Write didn't complete. Schedule write I/O callback to
                    // pick up from where this write has left.
                    enableWrite();
                    return;
                }
            }
        }

        /**
         * Closes this channel.
         */
        @Override
        public void closeChannel() throws IOException {
            mSelectionKey.cancel();
            synchronized (this) {
                mNotifications.clear();
            }
            mChannel.close();
        }

        /***********************************************************************
         * EmulatorAsyncChannel implementation
         **********************************************************************/

        /**
         * Reads data from the channel. This method is invoked from the I/O loop
         * when data is available for reading on this channel. When reading from
         * a channel we read character-by-character, building the query string
         * until zero-terminator is read. When zero-terminator is read, we
         * handle the query, and start building the new query string.
         *
         * @throws IOException
         */
        private void onRead() throws IOException, ClosedChannelException {
            int count = mChannel.read(mIn);
            Logv("onRead: " + count);
            while (count == 1) {
                final char c = (char) mIn.array()[0];
                mIn.reset();
                if (c == '\0') {
                    // Zero-terminator is read. Process the query, and reset
                    // the query string.
                    onQueryReceived(mQuery);
                    mQuery = "";
                } else {
                    // Continue building the query string.
                    mQuery += c;
                }
                count = mChannel.read(mIn);
            }

            if (count == -1) {
                // Channel got disconnected.
                throw new ClosedChannelException();
            } else {
                // "Don't block" in effect. Will get back to reading as soon as
                // read I/O is available.
                assert (count == 0);
            }
        }

        /**
         * Writes data to the channel. This method is ivnoked from the I/O loop
         * when data is available for writing on this channel.
         *
         * @throws IOException
         */
        private void onWrite() throws IOException {
            if (mOut != null && mOut.hasRemaining()) {
                // Continue writing to the channel.
                mChannel.write(mOut);
                if (mOut.hasRemaining()) {
                    // Write is still incomplete. Come back to it when write I/O
                    // becomes available.
                    return;
                }
            }

            // We're done with the current message. Lets see if we've
            // accumulated some more while this write was in progress.
            synchronized (this) {
                // Dequeue next message into mOut.
                if (!dequeueMessage()) {
                    // Nothing left to write.
                    disableWrite();
                    mOut = null;
                    return;
                }
                // We don't really want to run a big loop here, flushing the
                // message queue. The reason is that we're inside the I/O loop,
                // so we don't want to block others for long. So, we will
                // continue with queue flushing next time we're picked up by
                // write I/O event.
            }
        }

        /**
         * Dequeues messages that were yielding to the write in progress.
         * Messages will be dequeued directly to the mOut, so it's ready to be
         * sent when this method returns. NOTE: This method must be called from
         * within synchronized(this).
         *
         * @return true if messages were dequeued, or false if message queue was
         *         empty.
         */
        private boolean dequeueMessage() {
            // It's tempting to dequeue all messages here, but in practice it's
            // less performant than dequeuing just one.
            if (!mNotifications.isEmpty()) {
                mOut = ByteBuffer.wrap(mNotifications.remove(0).getBytes());
                return true;
            } else {
                return false;
            }
        }

        /**
         * Enables write I/O callbacks.
         */
        private void enableWrite() {
            mSelectionKey.interestOps(SelectionKey.OP_READ | SelectionKey.OP_WRITE);
            // Looks like we must wake up the selector. Otherwise it's not going
            // to immediately pick up on the change that we just made.
            mSelectionKey.selector().wakeup();
        }

        /**
         * Disables write I/O callbacks.
         */
        private void disableWrite() {
            mSelectionKey.interestOps(SelectionKey.OP_READ);
        }
    } // EmulatorChannel

    /***************************************************************************
     * Emulator public API
     **************************************************************************/

    /**
     * Constructs Emulator instance.
     *
     * @param port TCP port where emulator connects.
     * @param ctype Defines connection type to use (sync / async). See comments
     *            to Emulator class for more info.
     * @throws IOException
     */
    public Emulator(int port, EmulatorConnectionType ctype) throws IOException {
        constructEmulator(port, ctype);
    }

    /**
     * Constructs Emulator instance.
     *
     * @param port TCP port where emulator connects.
     * @param ctype Defines connection type to use (sync / async). See comments
     *            to Emulator class for more info.
     * @param listener Emulator event listener.
     * @throws IOException
     */
    public Emulator(int port, EmulatorConnectionType ctype, OnEmulatorListener listener)
            throws IOException {
        mListener = listener;
        constructEmulator(port, ctype);
    }

    /**
     * Constructs Emulator instance.
     *
     * @param port TCP port where emulator connects.
     * @param ctype Defines connection type to use (sync / async). See comments
     *            to Emulator class for more info.
     * @throws IOException
     */
    private void constructEmulator(int port, EmulatorConnectionType ctype) throws IOException {
        mConnectionType = ctype;
        // Create I/O looper.
        mSelector = SelectorProvider.provider().openSelector();

        // Create non-blocking server socket that would listen for connections,
        // and bind it to the given port on the local host.
        mServerSocket = ServerSocketChannel.open();
        mServerSocket.configureBlocking(false);
        InetAddress local = InetAddress.getLocalHost();
        InetSocketAddress address = new InetSocketAddress(local, port);
        mServerSocket.socket().bind(address);

        // Register 'accept' I/O on the server socket.
        mServerSocket.register(mSelector, SelectionKey.OP_ACCEPT);

        // Start I/O looper and dispatcher.
        new Thread(new Runnable() {
            @Override
            public void run() {
                runIOLooper();
            }
        }).start();
    }

    /**
     * Sends a notification message to the emulator via 'event' channel.
     *
     * @param msg
     */
    public void sendNotification(String msg) {
        if (mIsConnected) {
            try {
                mEventChannel.sendMessage(msg);
            } catch (IOException e) {
                onLostConnection();
            }
        } else {
            Logw("Attempt to send '" + msg + "' to a disconnected Emulator");
        }
    }

    /**
     * Sets or removes a listener to the events generated by this emulator
     * instance.
     *
     * @param listener Listener to set. Passing null with this parameter will
     *            remove the current listener (if there was one).
     */
    public void setOnEmulatorListener(OnEmulatorListener listener) {
        synchronized (this) {
            mListener = listener;
        }
        // Make sure that new listener knows the connection status.
        if (mListener != null) {
            if (mIsConnected) {
                mListener.onEmulatorConnected();
            } else if (mIsDisconnected) {
                mListener.onEmulatorDisconnected();
            }
        }
    }

    /***************************************************************************
     * Emulator events
     **************************************************************************/

    /**
     * Called when emulator is connected. NOTE: This method is called from the
     * I/O loop, so all communication with the emulator will be "on hold" until
     * this method returns.
     */
    private void onConnected() {
        OnEmulatorListener listener;
        synchronized (this) {
            listener = mListener;
        }
        if (listener != null) {
            listener.onEmulatorConnected();
        }
    }

    /**
     * Called when emulator is disconnected. NOTE: This method could be called
     * from the I/O loop, in which case all communication with the emulator will
     * be "on hold" until this method returns.
     */
    private void onDisconnected() {
        OnEmulatorListener listener;
        synchronized (this) {
            listener = mListener;
        }
        if (listener != null) {
            listener.onEmulatorDisconnected();
        }
    }

    /**
     * Called when a query is received from the emulator. NOTE: This method
     * could be called from the I/O loop, in which case all communication with
     * the emulator will be "on hold" until this method returns.
     *
     * @param query Name of the query received from the emulator.
     * @param param Query parameters.
     * @return Zero-terminated reply string. String must be formatted as such:
     *         "ok|ko[:reply data]"
     */
    private String onQuery(String query, String param) {
        OnEmulatorListener listener;
        synchronized (this) {
            listener = mListener;
        }
        if (listener != null) {
            return listener.onEmulatorQuery(query, param);
        } else {
            return "ko:Service is detached.\0";
        }
    }

    /***************************************************************************
     * Emulator implementation
     **************************************************************************/

    /**
     * Loops on the selector, handling and dispatching I/O events.
     */
    private void runIOLooper() {
        try {
            Logv("Waiting on Emulator to connect...");
            while (mSelector.select() >= 0) {
                Set<SelectionKey> readyKeys = mSelector.selectedKeys();
                Iterator<SelectionKey> i = readyKeys.iterator();
                while (i.hasNext()) {
                    SelectionKey sk = i.next();
                    i.remove();
                    if (sk.isAcceptable()) {
                        final int ready = sk.readyOps();
                        if ((ready & SelectionKey.OP_ACCEPT) != 0) {
                            // Accept new connection.
                            onAccept(((ServerSocketChannel) sk.channel()).accept());
                        }
                    } else {
                        // Read / write events are expected only on a 'query',
                        // or 'event' asynchronous channels.
                        EmulatorAsyncChannel esc = (EmulatorAsyncChannel) sk.attachment();
                        if (esc != null) {
                            final int ready = sk.readyOps();
                            if ((ready & SelectionKey.OP_READ) != 0) {
                                // Read data.
                                esc.onRead();
                            }
                            if ((ready & SelectionKey.OP_WRITE) != 0) {
                                // Write data.
                                esc.onWrite();
                            }
                        } else {
                            Loge("No emulator channel found in selection key.");
                        }
                    }
                }
            }
        } catch (ClosedSelectorException e) {
        } catch (IOException e) {
        }

        // Destroy connection on any I/O failure.
        onLostConnection();
    }

    /**
     * Accepts new connection from the emulator.
     *
     * @param channel Connecting socket channel.
     * @throws IOException
     */
    private void onAccept(SocketChannel channel) throws IOException {
        // Make sure we're not connected yet.
        if (mEventChannel != null && mQueryChannel != null) {
            // We don't accept any more connections after both channels were
            // connected.
            Loge("Emulator is connecting to the already connected instance.");
            channel.close();
            return;
        }

        // According to the protocol, each channel identifies itself as a query
        // or event channel, sending a "cmd", or "event" message right after
        // the connection.
        Socket socket = channel.socket();
        String socket_type = readSocketString(socket);
        if (socket_type.contentEquals(EmulatorChannel.QUERY_CHANNEL)) {
            if (mQueryChannel == null) {
                // TODO: Find better way to do that!
                socket.getOutputStream().write("ok\0".getBytes());
                if (mConnectionType == EmulatorConnectionType.ASYNC_CONNECTION) {
                    mQueryChannel = new EmulatorAsyncChannel(channel);
                    Logv("Asynchronous query channel is registered.");
                } else {
                    mQueryChannel = new EmulatorSyncChannel(channel.socket());
                    Logv("Synchronous query channel is registered.");
                }
            } else {
                // TODO: Find better way to do that!
                socket.getOutputStream().write("ko:Duplicate,\0".getBytes());
                Loge("Duplicate query channel.");
                channel.close();
                return;
            }
        } else if (socket_type.contentEquals(EmulatorChannel.EVENT_CHANNEL)) {
            if (mEventChannel == null) {
                // TODO: Find better way to do that!
                socket.getOutputStream().write("ok\0".getBytes());
                if (mConnectionType == EmulatorConnectionType.ASYNC_CONNECTION) {
                    mEventChannel = new EmulatorAsyncChannel(channel);
                    Logv("Asynchronous event channel is registered.");
                } else {
                    mEventChannel = new EmulatorSyncChannel(channel.socket());
                    Logv("Synchronous event channel is registered.");
                }
            } else {
                socket.getOutputStream().write("ko:Duplicate,\0".getBytes());
                Loge("Duplicate event channel.");
                channel.close();
                return;
            }
        } else {
            Loge("Unknown channel is connecting: " + socket_type);
            channel.close();
            return;
        }

        // Lets see if connection is complete...
        if (mEventChannel != null && mQueryChannel != null) {
            // When both, query and event channels are connected, the emulator
            // is considered to be connected.
            Logv("... Emulator is connected.");
            mIsConnected = true;
            onConnected();
        }
    }

    /**
     * Called when connection to any of the channels has been lost.
     */
    private void onLostConnection() {
        // Since we're multithreaded, there can be multiple "bangs" from those
        // threads. We should only handle the first one.
        boolean first_time = false;
        synchronized (this) {
            first_time = mIsConnected;
            mIsConnected = false;
            mIsDisconnected = true;
        }
        if (first_time) {
            Logw("Connection with the emulator is lost.");
            synchronized (this) {
                // Close all channels.
                if (mSelector != null) {
                    try {
                        if (mEventChannel != null) {
                            mEventChannel.closeChannel();
                        }
                        if (mQueryChannel != null) {
                            mQueryChannel.closeChannel();
                        }
                        mServerSocket.close();
                        mSelector.close();
                    } catch (IOException e) {
                        Loge("onLostConnection exception: " + e.getMessage());
                    }
                }
            }

            // Notify the app about lost connection.
            onDisconnected();
        }
    }

    /**
     * Reads zero-terminated string from a synchronous socket.
     *
     * @param socket Socket to read string from. Must be a synchronous socket.
     * @return String read from the socket.
     * @throws IOException
     */
    private static String readSocketString(Socket socket) throws IOException {
        String str = "";

        // Current characted received from the input stream.
        int current_byte = 0;

        // With port forwarding there is no reliable way how to detect
        // socket disconnection, other than checking on the input stream
        // to die ("end of stream" condition). That condition is reported
        // when input stream's read() method returns -1.
        while (socket.isConnected() && current_byte != -1) {
            // Character by character read the input stream, and accumulate
            // read characters in the command string. The end of the command
            // is indicated with zero character.
            current_byte = socket.getInputStream().read();
            if (current_byte != -1) {
                if (current_byte == 0) {
                    // String is completed.
                    return str;
                } else {
                    // Append read character to the string.
                    str += (char) current_byte;
                }
            }
        }

        // Got disconnected!
        throw new ClosedChannelException();
    }

    /***************************************************************************
     * Logging wrappers
     **************************************************************************/

    private void Loge(String log) {
        Log.e(TAG, log);
    }

    private void Logw(String log) {
        Log.w(TAG, log);
    }

    private void Logv(String log) {
        Log.v(TAG, log);
    }
}
