package json.ext;

import org.jcodings.Encoding;
import org.jruby.util.ByteList;

import java.io.IOException;

public class SegmentedByteListDirectOutputStream extends AbstractByteListDirectOutputStream {
    private static final int DEFAULT_CAPACITY = 1024;

    private int totalLength;
    // Why 21? The minimum segment size is 1024 bytes. If we double the segment size each time 
    // we need a new segment, we only need 21 segments to reach the maximum array size in Java.
    private byte[][] segments = new byte[21][];
    private int currentSegmentIndex;
    private int currentSegmentLength;
    private byte[] currentSegment;

    SegmentedByteListDirectOutputStream(int size) {
        currentSegment = new byte[Math.max(size, DEFAULT_CAPACITY)];
        segments[0] = currentSegment;
    }

    public ByteList toByteListDirect(Encoding encoding) {
        byte[] buffer = new byte[totalLength];
        int pos = 0;
        // We handle the current segment separately.
        for (int i = 0; i < currentSegmentIndex; i++) {
            byte[] segment = segments[i];
            System.arraycopy(segment, 0, buffer, pos, segment.length);
            pos += segment.length;
        }
        System.arraycopy(currentSegment, 0, buffer, pos, currentSegmentLength);
        return new ByteList(buffer, 0, totalLength, encoding, false);
    }

    @Override
    public void write(int b) throws IOException {
        if (currentSegmentLength == currentSegment.length) {
            if (totalLength + 1 < 0) {
                throw new IOException("Total length exceeds maximum length of an array.");
            }
            currentSegmentIndex++;
            int capacity = currentSegment.length * 2;
            capacity = (capacity < 0) ? DEFAULT_CAPACITY : capacity;
            currentSegment = new byte[capacity];
            currentSegmentLength = 0;
            segments[currentSegmentIndex] = currentSegment;
        }
        currentSegment[currentSegmentLength++] = (byte) b;
        totalLength++;
    }

    @Override
    public void write(byte[] bytes, int start, int length) throws IOException {
        int remaining = length;

        while (remaining > 0) {
            if (currentSegmentLength == currentSegment.length) {
                if (totalLength + remaining < 0) {
                    throw new IOException("Total length exceeds maximum length of an array.");
                }
                currentSegmentIndex++;
                int capacity = currentSegment.length << 1;
                capacity = (capacity < 0) ? DEFAULT_CAPACITY : capacity;
                capacity = (capacity < remaining) ? remaining : capacity;
                currentSegment = new byte[capacity];
                currentSegmentLength = 0;
                segments[currentSegmentIndex] = currentSegment;
            }
            int toWrite = Math.min(remaining, currentSegment.length - currentSegmentLength);
            System.arraycopy(bytes, start, currentSegment, currentSegmentLength, toWrite);
            currentSegmentLength += toWrite;
            start += toWrite;
            remaining -= toWrite;
        }
        totalLength += length;
    }

    @Override
    public void write(byte[] bytes) throws IOException {
        write(bytes, 0, bytes.length);
    }
}
