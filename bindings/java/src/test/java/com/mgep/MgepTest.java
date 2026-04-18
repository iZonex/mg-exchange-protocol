package com.mgep;

/**
 * Minimal test harness — intentionally framework-free so the bindings
 * have no build dependencies beyond a JDK. A full project would swap
 * this for JUnit 5.
 *
 * Run with: javac -d out src/main/java/com/mgep/*.java src/test/java/com/mgep/*.java && java -cp out com.mgep.MgepTest
 */
public final class MgepTest {
    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) {
        testSizes();
        testNewOrderRoundtrip();
        testDecimalEncoding();
        testHeaderDecode();

        System.out.printf("%nResults: %d passed, %d failed%n", passed, failed);
        if (failed > 0) System.exit(1);
    }

    private static void testSizes() {
        assertEq(Mgep.NewOrderSingle.SIZE, 48, "NewOrderSingle size");
        assertEq(Mgep.ExecutionReport.SIZE, 88, "ExecutionReport size");
        assertEq(Mgep.BusinessReject.SIZE, 16, "BusinessReject size");
        assertEq(Mgep.BookSnapshotBegin.SIZE, 40, "BookSnapshotBegin size");
        assertEq(Mgep.BookSnapshotLevel.SIZE, 40, "BookSnapshotLevel size");
        assertEq(Mgep.BookSnapshotEnd.SIZE, 32, "BookSnapshotEnd size");
        assertEq(Mgep.ClockStatus.SIZE, 40, "ClockStatus size");
    }

    private static void testNewOrderRoundtrip() {
        byte[] bytes = Mgep.encodeNewOrder(
            42L, 99L, 7,
            Mgep.SIDE_BUY, Mgep.ORDER_TYPE_LIMIT,
            150.25, 100.0,
            Mgep.TIF_DAY, 1, 1L, 0L);

        assertEq(bytes.length, Mgep.FULL_HEADER_SIZE + Mgep.NewOrderSingle.SIZE,
                "encoded size");

        Mgep.FullHeader hdr = Mgep.FullHeader.decode(bytes);
        assertTrue(hdr != null && hdr.isValid(), "header valid");
        assertEq(hdr.schemaId, Mgep.SCHEMA_TRADING, "schema_id");
        assertEq(hdr.messageType, Mgep.MSG_NEW_ORDER, "message_type");

        Mgep.NewOrderSingle order = Mgep.NewOrderSingle.decode(bytes);
        assertEq(order.orderId, 42L, "order_id");
        assertEq(order.clientOrderId, 99L, "client_order_id");
        assertEq(order.instrumentId, 7, "instrument_id");
        assertEq(order.side, Mgep.SIDE_BUY, "side");
        assertCloseTo(order.priceAsDouble(), 150.25, 1e-6, "price");
        assertCloseTo(order.quantityAsDouble(), 100.0, 1e-6, "quantity");
    }

    private static void testDecimalEncoding() {
        long enc = Mgep.encodeDecimal(150.25);
        assertEq(enc, 15_025_000_000L, "decimal encode");
        double dec = Mgep.decodeDecimal(enc);
        assertCloseTo(dec, 150.25, 1e-9, "decimal roundtrip");
        // NULL sentinel
        assertEq(Mgep.encodeDecimal(Double.NaN), Mgep.DECIMAL_NULL, "NaN → DECIMAL_NULL");
    }

    private static void testHeaderDecode() {
        // Malformed buffer → null
        assertTrue(Mgep.FullHeader.decode(new byte[16]) == null, "short buffer rejected");
        // Zero buffer → invalid magic
        Mgep.FullHeader h = Mgep.FullHeader.decode(new byte[Mgep.FULL_HEADER_SIZE]);
        assertTrue(h != null && !h.isValid(), "zero magic invalid");
    }

    // ─── Primitive assertions ──────────────────────────────

    private static void assertEq(long a, long b, String msg) {
        if (a == b) { passed++; System.out.println("PASS: " + msg); }
        else { failed++; System.out.printf("FAIL: %s — %d != %d%n", msg, a, b); }
    }

    private static void assertCloseTo(double a, double b, double tol, String msg) {
        if (Math.abs(a - b) < tol) { passed++; System.out.println("PASS: " + msg); }
        else { failed++; System.out.printf("FAIL: %s — %f !≈ %f%n", msg, a, b); }
    }

    private static void assertTrue(boolean cond, String msg) {
        if (cond) { passed++; System.out.println("PASS: " + msg); }
        else { failed++; System.out.println("FAIL: " + msg); }
    }
}
