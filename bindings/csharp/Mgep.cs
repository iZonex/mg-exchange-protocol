// MGEP C# bindings — pure-managed wire layout (no native library required).
//
// Scope mirrors the Python binding:
//   * Wire structs for every core block via [StructLayout(LayoutKind.Sequential)]
//   * Encode helpers that pack headers + core bytes
//   * Decode dispatch keyed on (schema_id, message_type)
//   * Flex string parser for optional text fields
//
// Because MGEP's wire format is zero-copy and all core blocks are
// `#[repr(C)]` in Rust, they map directly onto `[StructLayout]`
// C# structs. No C ABI shim is needed — managed code reads the
// bytes directly via `MemoryMarshal`.
//
// Tested against .NET 8. Should work on Mono / Unity too.

using System;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;

namespace MGEP
{
    // ═══════════════════════════════════════════════════════════
    // Constants
    // ═══════════════════════════════════════════════════════════

    public static class Wire
    {
        public const ushort Magic = 0x474D; // "MG"
        public const byte Version = 1;
        public const int FrameHeaderSize = 8;
        public const int FullHeaderSize = 32;
        public const int CoreBlockOffset = 32;

        public const long DecimalScale = 100_000_000L;
        public const long DecimalNull = long.MinValue;
        public const ulong TimestampNull = ulong.MaxValue;
    }

    public static class SchemaId
    {
        public const ushort Session = 0x0000;
        public const ushort Trading = 0x0001;
        public const ushort MarketData = 0x0002;
        public const ushort Quotes = 0x0003;
        public const ushort PostTrade = 0x0004;
        public const ushort Risk = 0x0005;
    }

    public enum Side : byte
    {
        Buy = 1,
        Sell = 2,
    }

    public enum OrderType : byte
    {
        Market = 1,
        Limit = 2,
        Stop = 3,
        StopLimit = 4,
    }

    public enum TimeInForce : ushort
    {
        Day = 1,
        GTC = 2,
        IOC = 3,
        FOK = 4,
        GTD = 5,
    }

    public enum ExecType : byte
    {
        New = 0,
        PartialFill = 1,
        Fill = 2,
        Canceled = 4,
        Replaced = 5,
        Rejected = 8,
    }

    // ═══════════════════════════════════════════════════════════
    // Headers
    // ═══════════════════════════════════════════════════════════

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct FrameHeader
    {
        public ushort Magic;
        public byte Flags;
        public byte Version;
        public uint MessageSize;

        public bool IsValid() => Magic == Wire.Magic;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct MessageHeader
    {
        public ushort SchemaId;
        public ushort MessageType;
        public uint SenderCompId;
        public ulong SequenceNum;
        public ulong CorrelationId;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct FullHeader
    {
        public FrameHeader Frame;
        public MessageHeader Message;
    }

    // ═══════════════════════════════════════════════════════════
    // Trading messages
    // ═══════════════════════════════════════════════════════════

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct NewOrderSingle
    {
        public const int Size = 48;

        public ulong OrderId;
        public ulong ClientOrderId;
        public uint InstrumentId;
        public byte Side;
        public byte OrderType;
        public ushort TimeInForce;
        public long Price;
        public long Quantity;
        public long StopPrice;

        public double PriceAsDouble() => Price == Wire.DecimalNull ? double.NaN : Price / (double)Wire.DecimalScale;
        public double QuantityAsDouble() => Quantity / (double)Wire.DecimalScale;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ExecutionReport
    {
        public const int Size = 88;

        public ulong OrderId;
        public ulong ClientOrderId;
        public ulong ExecId;
        public uint InstrumentId;
        public byte Side;
        public byte ExecType;
        public byte OrderStatus;
        public byte _Pad;
        public long Price;
        public long Quantity;
        public long LeavesQty;
        public long CumQty;
        public long LastPx;
        public long LastQty;
        public ulong TransactTime;

        public double LastPxAsDouble() => LastPx == Wire.DecimalNull ? double.NaN : LastPx / (double)Wire.DecimalScale;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct BusinessReject
    {
        public const int Size = 16;

        public uint RefSeqNum;
        public byte RefMsgType;
        public byte BusinessReason;
        public ushort _Pad;
        public ulong OrderId;
    }

    // ═══════════════════════════════════════════════════════════
    // Market data: snapshot recovery
    // ═══════════════════════════════════════════════════════════

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct BookSnapshotRequest
    {
        public const int Size = 16;
        public ulong RequestId;
        public uint InstrumentId;
        public uint MaxLevels;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct BookSnapshotBegin
    {
        public const int Size = 40;
        public ulong RequestId;
        public uint InstrumentId;
        public uint _Pad;
        public ulong LastAppliedSeq;
        public uint LevelCount;
        public uint _Pad2;
        public ulong SnapshotId;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct BookSnapshotLevel
    {
        public const int Size = 40;
        public ulong SnapshotId;
        public uint LevelIndex;
        public byte Side;
        public byte _Pad1;
        public byte _Pad2;
        public byte _Pad3;
        public long Price;
        public long Quantity;
        public uint OrderCount;
        public uint _Pad4;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct BookSnapshotEnd
    {
        public const int Size = 32;
        public ulong SnapshotId;
        public ulong FinalSeq;
        public ulong Checksum;
        public uint LevelCount;
        public uint _Pad;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ClockStatus
    {
        public const int Size = 40;
        public byte Source;
        public byte Quality;
        public byte _Pad0;
        public byte _Pad1;
        public byte _Pad2;
        public byte _Pad3;
        public byte _Pad4;
        public byte _Pad5;
        public ulong ObservedAt;
        public ulong LastSync;
        public ulong EstimatedDriftNs;
        public ulong ReferenceClockId;

        public bool IsRegulatoryGrade() => Quality == 1;
    }

    // ═══════════════════════════════════════════════════════════
    // Encoder
    // ═══════════════════════════════════════════════════════════

    public static class Encoder
    {
        /// <summary>Encode a NewOrderSingle into a freshly allocated byte[].</summary>
        public static byte[] EncodeNewOrder(
            ulong orderId,
            ulong clientOrderId,
            uint instrumentId,
            Side side,
            OrderType orderType,
            double price,
            double quantity,
            TimeInForce tif = TimeInForce.Day,
            double stopPrice = double.NaN,
            uint senderCompId = 1,
            ulong sequenceNum = 1,
            ulong correlationId = 0)
        {
            var core = new NewOrderSingle
            {
                OrderId = orderId,
                ClientOrderId = clientOrderId,
                InstrumentId = instrumentId,
                Side = (byte)side,
                OrderType = (byte)orderType,
                TimeInForce = (ushort)tif,
                Price = EncodeDecimal(price),
                Quantity = EncodeDecimal(quantity),
                StopPrice = EncodeDecimal(stopPrice),
            };

            uint total = (uint)(Wire.FullHeaderSize + NewOrderSingle.Size);
            var buf = new byte[total];

            // Frame header
            BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(0, 2), Wire.Magic);
            buf[2] = 0; // flags
            buf[3] = Wire.Version;
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(4, 4), total);

            // Message header
            BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(8, 2), SchemaId.Trading);
            BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(10, 2), 0x01); // NewOrderSingle
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(12, 4), senderCompId);
            BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(16, 8), sequenceNum);
            BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(24, 8), correlationId);

            // Core block — blit the struct bytes directly.
            MemoryMarshal.Write(buf.AsSpan(Wire.CoreBlockOffset), in core);

            return buf;
        }

        private static long EncodeDecimal(double value)
        {
            if (double.IsNaN(value)) return Wire.DecimalNull;
            return (long)(value * Wire.DecimalScale);
        }
    }

    // ═══════════════════════════════════════════════════════════
    // Decoder
    // ═══════════════════════════════════════════════════════════

    public static class Decoder
    {
        /// <summary>
        /// Decode the message header. Returns <c>null</c> if the buffer
        /// is too short or the magic bytes are wrong.
        /// </summary>
        public static FullHeader? DecodeHeader(ReadOnlySpan<byte> buf)
        {
            if (buf.Length < Wire.FullHeaderSize) return null;
            var hdr = MemoryMarshal.Read<FullHeader>(buf);
            if (!hdr.Frame.IsValid()) return null;
            return hdr;
        }

        /// <summary>Decode a NewOrderSingle core block.</summary>
        public static NewOrderSingle DecodeNewOrder(ReadOnlySpan<byte> buf)
            => MemoryMarshal.Read<NewOrderSingle>(buf.Slice(Wire.CoreBlockOffset, NewOrderSingle.Size));

        /// <summary>Decode an ExecutionReport core block.</summary>
        public static ExecutionReport DecodeExecReport(ReadOnlySpan<byte> buf)
            => MemoryMarshal.Read<ExecutionReport>(buf.Slice(Wire.CoreBlockOffset, ExecutionReport.Size));

        /// <summary>Decode a BusinessReject core block.</summary>
        public static BusinessReject DecodeBusinessReject(ReadOnlySpan<byte> buf)
            => MemoryMarshal.Read<BusinessReject>(buf.Slice(Wire.CoreBlockOffset, BusinessReject.Size));

        /// <summary>Decode a BookSnapshotBegin core block.</summary>
        public static BookSnapshotBegin DecodeSnapshotBegin(ReadOnlySpan<byte> buf)
            => MemoryMarshal.Read<BookSnapshotBegin>(buf.Slice(Wire.CoreBlockOffset, BookSnapshotBegin.Size));

        /// <summary>Decode a BookSnapshotLevel core block.</summary>
        public static BookSnapshotLevel DecodeSnapshotLevel(ReadOnlySpan<byte> buf)
            => MemoryMarshal.Read<BookSnapshotLevel>(buf.Slice(Wire.CoreBlockOffset, BookSnapshotLevel.Size));

        /// <summary>Decode a BookSnapshotEnd core block.</summary>
        public static BookSnapshotEnd DecodeSnapshotEnd(ReadOnlySpan<byte> buf)
            => MemoryMarshal.Read<BookSnapshotEnd>(buf.Slice(Wire.CoreBlockOffset, BookSnapshotEnd.Size));

        /// <summary>Decode a ClockStatus core block.</summary>
        public static ClockStatus DecodeClockStatus(ReadOnlySpan<byte> buf)
            => MemoryMarshal.Read<ClockStatus>(buf.Slice(Wire.CoreBlockOffset, ClockStatus.Size));

        /// <summary>
        /// Parse an optional flex string by field_id. Returns null when
        /// the field is absent or the buffer is malformed.
        /// </summary>
        public static string? ParseFlexString(ReadOnlySpan<byte> buf, int coreSize, ushort fieldId = 1)
        {
            int flexStart = Wire.CoreBlockOffset + coreSize;
            if (buf.Length < flexStart + 2) return null;
            ushort count = BinaryPrimitives.ReadUInt16LittleEndian(buf.Slice(flexStart, 2));
            if (count > 32) count = 32; // mirror Rust MAX_FLEX_FIELDS
            int entries = flexStart + 2;
            int data = entries + count * 4;
            for (int i = 0; i < count; i++)
            {
                int p = entries + i * 4;
                if (p + 4 > buf.Length) return null;
                ushort fid = BinaryPrimitives.ReadUInt16LittleEndian(buf.Slice(p, 2));
                ushort foff = BinaryPrimitives.ReadUInt16LittleEndian(buf.Slice(p + 2, 2));
                if (fid == fieldId)
                {
                    int pos = data + foff;
                    if (pos + 3 > buf.Length) return null;
                    if (buf[pos] != 0x0B) return null; // FlexType::String = 0x0B
                    ushort slen = BinaryPrimitives.ReadUInt16LittleEndian(buf.Slice(pos + 1, 2));
                    int start = pos + 3;
                    if (start + slen > buf.Length) return null;
                    return Encoding.UTF8.GetString(buf.Slice(start, slen));
                }
            }
            return null;
        }
    }
}
