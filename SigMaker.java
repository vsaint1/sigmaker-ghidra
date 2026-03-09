// SigMaker.java
//
// INSTALL : Copy to %USERPROFILE%\ghidra_scripts\
// RUN     : Script Manager -> SigMaker  (or assign CTRL+ALT+S)
//
//@author vsaint1
//@category Signature
//@keybinding CTRL ALT S
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;

public class SigMaker extends GhidraScript {

    private static int     S_ACTION          = 0;
    private static int     S_FORMAT          = 0;
    private static boolean S_WC_OPERANDS     = true;
    private static boolean S_CONTINUE_SCOPE  = false;
    private static boolean S_OP_JUMPS        = true;
    private static boolean S_OP_CALLS        = true;
    private static boolean S_OP_IMMEDIATE    = true;
    private static boolean S_OP_DISPLACEMENT = true;
    private static boolean S_OP_DIRECT       = true;
    private static boolean S_OP_MEMORY       = true;

    // Singleton — only one search window open at a time
    private static JFrame s_searchFrame = null;

    private static final class SigByte {
        final byte    value;
        final boolean wildcard;
        SigByte(byte v, boolean w) { value = v; wildcard = w; }
    }

    @Override
    public void run() throws Exception {
        if (currentLocation == null) {
            printerr("[SigMaker] No cursor location. Open a program and place the cursor in the listing.");
            return;
        }
        SwingUtilities.invokeLater(this::showMainDialog);
    }

    // =========================================================================
    // MAIN DIALOG
    // =========================================================================
    private void showMainDialog() {
        JDialog dlg = new JDialog((Frame) null, "Signature Maker v1.0.5", true);
        dlg.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        dlg.setResizable(false);

        JPanel root = new JPanel();
        root.setLayout(new BoxLayout(root, BoxLayout.Y_AXIS));
        root.setBorder(new EmptyBorder(10, 10, 10, 10));

        root.add(sectionLabel("Select action:"));
        root.add(Box.createVerticalStrut(4));

        ButtonGroup actGroup = new ButtonGroup();
        JRadioButton rbCreate = radio("Create unique Signature for current code address", actGroup);
        JRadioButton rbXRef   = radio("Find shortest XREF Signature for current data or code address", actGroup);
        JRadioButton rbCopy   = radio("Copy selected code", actGroup);
        JRadioButton rbSearch = radio("Search for a signature", actGroup);

        JPanel actPanel = bordered(rbCreate, rbXRef, rbCopy, rbSearch);
        root.add(actPanel);

        JRadioButton[] actBtns = { rbCreate, rbXRef, rbCopy, rbSearch };
        actBtns[Math.min(S_ACTION, 3)].setSelected(true);

        root.add(Box.createVerticalStrut(6));
        root.add(sectionLabel("Output format:"));
        root.add(Box.createVerticalStrut(4));

        ButtonGroup fmtGroup = new ButtonGroup();
        JRadioButton rbIDA  = radio("IDA Signature",                        fmtGroup);
        JRadioButton rbX64  = radio("x64Dbg Signature",                     fmtGroup);
        JRadioButton rbCArr = radio("C Byte Array Signature + String mask", fmtGroup);
        JRadioButton rbCRaw = radio("C Raw Bytes Signature + Bitmask",      fmtGroup);

        JPanel fmtPanel = bordered(rbIDA, rbX64, rbCArr, rbCRaw);
        root.add(fmtPanel);

        JRadioButton[] fmtBtns = { rbIDA, rbX64, rbCArr, rbCRaw };
        fmtBtns[Math.min(S_FORMAT, 3)].setSelected(true);

        root.add(Box.createVerticalStrut(6));
        root.add(sectionLabel("Options:"));
        root.add(Box.createVerticalStrut(4));

        JCheckBox cbWcOps     = new JCheckBox("Wildcards for operands",               S_WC_OPERANDS);
        JCheckBox cbContScope = new JCheckBox("Continue when leaving function scope",  S_CONTINUE_SCOPE);
        JButton   btnOpTypes  = new JButton("Operand types...");
        btnOpTypes.setMargin(new Insets(2, 6, 2, 6));

        JPanel optInner = new JPanel();
        optInner.setLayout(new BoxLayout(optInner, BoxLayout.Y_AXIS));
        optInner.add(cbWcOps);
        optInner.add(cbContScope);
        optInner.add(Box.createVerticalStrut(4));
        JPanel btnRow0 = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        btnRow0.add(btnOpTypes);
        optInner.add(btnRow0);

        JPanel optPanel = new JPanel(new BorderLayout());
        optPanel.add(optInner);
        optPanel.setBorder(new CompoundBorder(
                BorderFactory.createEtchedBorder(),
                new EmptyBorder(6, 8, 6, 8)));
        root.add(optPanel);
        root.add(Box.createVerticalStrut(10));

        JPanel bottomRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        JButton btnOK     = new JButton("OK");
        JButton btnCancel = new JButton("Cancel");
        btnOK.setPreferredSize(new Dimension(72, btnOK.getPreferredSize().height));
        btnCancel.setPreferredSize(new Dimension(72, btnCancel.getPreferredSize().height));
        bottomRow.add(btnOK);
        bottomRow.add(btnCancel);
        root.add(bottomRow);

        btnOpTypes.setEnabled(cbWcOps.isSelected());
        cbWcOps.addActionListener(e -> btnOpTypes.setEnabled(cbWcOps.isSelected()));

        btnOpTypes.addActionListener(e -> {
            dlg.setVisible(false);
            showOperandTypesDialog(() -> dlg.setVisible(true));
        });

        btnCancel.addActionListener(e -> dlg.dispose());

        btnOK.addActionListener(e -> {
            S_ACTION         = selectedIndex(actBtns);
            S_FORMAT         = selectedIndex(fmtBtns);
            S_WC_OPERANDS    = cbWcOps.isSelected();
            S_CONTINUE_SCOPE = cbContScope.isSelected();
            dlg.dispose();
            runAsync(this::executeAction);
        });

        dlg.getRootPane().setDefaultButton(btnOK);
        dlg.setContentPane(root);
        dlg.pack();
        dlg.setMinimumSize(new Dimension(400, dlg.getHeight()));
        dlg.setLocationRelativeTo(null);
        dlg.setVisible(true);
    }

    // =========================================================================
    // OPERAND TYPES SUB-DIALOG
    // =========================================================================
    private void showOperandTypesDialog(Runnable onClose) {
        JDialog dlg = new JDialog((Frame) null, "Operand types", true);
        dlg.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        dlg.setResizable(false);

        JPanel root = new JPanel();
        root.setLayout(new BoxLayout(root, BoxLayout.Y_AXIS));
        root.setBorder(new EmptyBorder(10, 12, 10, 12));
        root.add(new JLabel("Wildcard the following operand types:"));
        root.add(Box.createVerticalStrut(8));

        JCheckBox cbJumps  = new JCheckBox("Jumps / branches",              S_OP_JUMPS);
        JCheckBox cbCalls  = new JCheckBox("Calls",                         S_OP_CALLS);
        JCheckBox cbImm    = new JCheckBox("Immediate values",              S_OP_IMMEDIATE);
        JCheckBox cbDisp   = new JCheckBox("Displacements (e.g. [rbp-8])", S_OP_DISPLACEMENT);
        JCheckBox cbDirect = new JCheckBox("Direct offsets / addresses",    S_OP_DIRECT);
        JCheckBox cbMem    = new JCheckBox("Memory references",             S_OP_MEMORY);

        for (JCheckBox cb : new JCheckBox[]{cbJumps, cbCalls, cbImm, cbDisp, cbDirect, cbMem}) {
            root.add(cb);
            root.add(Box.createVerticalStrut(2));
        }
        root.add(Box.createVerticalStrut(8));

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        JButton btnOK     = new JButton("OK");
        JButton btnCancel = new JButton("Cancel");
        btnOK.setPreferredSize(new Dimension(72, btnOK.getPreferredSize().height));
        btnCancel.setPreferredSize(new Dimension(72, btnCancel.getPreferredSize().height));
        btnRow.add(btnOK);
        btnRow.add(btnCancel);
        root.add(btnRow);

        btnOK.addActionListener(e -> {
            S_OP_JUMPS        = cbJumps.isSelected();
            S_OP_CALLS        = cbCalls.isSelected();
            S_OP_IMMEDIATE    = cbImm.isSelected();
            S_OP_DISPLACEMENT = cbDisp.isSelected();
            S_OP_DIRECT       = cbDirect.isSelected();
            S_OP_MEMORY       = cbMem.isSelected();
            dlg.dispose();
            if (onClose != null) onClose.run();
        });
        btnCancel.addActionListener(e -> { dlg.dispose(); if (onClose != null) onClose.run(); });
        dlg.getRootPane().setDefaultButton(btnOK);
        dlg.setContentPane(root);
        dlg.pack();
        dlg.setLocationRelativeTo(null);
        dlg.setVisible(true);
    }

    // =========================================================================
    // SEARCH DIALOG
    //
    // Fixes applied:
    //   1. JFrame instead of JDialog(null) → own taskbar button, shows in Alt+Tab
    //   2. setAlwaysOnTop(true)            → never buried under Ghidra windows
    //   3. Singleton (s_searchFrame)       → re-running script focuses existing
    //                                        window instead of opening a duplicate
    //   4. WindowAdapter clears singleton  → no stale reference after close
    //   5. "📌 Pin" toggle button          → user can disable always-on-top if
    //                                        they want to work behind the window
    //   6. "Clear" button                  → reset field + results in one click
    //   7. Double-click result line        → navigate to address in listing
    //   8. Status bar                      → shows match count / search state
    // =========================================================================
    private void showSearchDialog() {
        // ── Singleton: if window already exists, just raise it ────────────
        if (s_searchFrame != null && s_searchFrame.isDisplayable()) {
            s_searchFrame.setVisible(true);
            s_searchFrame.toFront();
            s_searchFrame.requestFocus();
            return;
        }

        JFrame frame = new JFrame("SigMaker — Search for signature");
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        // Always-on-top so it never gets lost behind Ghidra
        frame.setAlwaysOnTop(true);
        s_searchFrame = frame;

        // Clear singleton ref when the window is actually closed
        frame.addWindowListener(new WindowAdapter() {
            @Override public void windowClosed(WindowEvent e) {
                s_searchFrame = null;
            }
        });

        // ── Toolbar row: pin toggle ───────────────────────────────────────
        JToggleButton btnPin = new JToggleButton("📌 Always on top", true);
        btnPin.setMargin(new Insets(2, 6, 2, 6));
        btnPin.setFont(btnPin.getFont().deriveFont(Font.PLAIN, 11f));
        btnPin.addActionListener(e -> frame.setAlwaysOnTop(btnPin.isSelected()));

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        toolbar.setBorder(new MatteBorder(0, 0, 1, 0,
                UIManager.getColor("Separator.foreground") != null
                        ? UIManager.getColor("Separator.foreground") : Color.GRAY));
        toolbar.add(btnPin);

        // ── Input area ────────────────────────────────────────────────────
        JLabel lbl = new JLabel("Signature (auto-detect: IDA / x64Dbg / C Byte Array / C Raw Bytes):");
        lbl.setBorder(new EmptyBorder(0, 0, 3, 0));

        JTextField sigField = new JTextField();
        sigField.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        JButton btnFind  = new JButton("Find");
        JButton btnClear = new JButton("Clear");
        JButton btnClose = new JButton("Close");
        btnFind .setPreferredSize(new Dimension(72, btnFind .getPreferredSize().height));
        btnClear.setPreferredSize(new Dimension(72, btnClear.getPreferredSize().height));
        btnClose.setPreferredSize(new Dimension(72, btnClose.getPreferredSize().height));

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        btnRow.add(btnFind);
        btnRow.add(btnClear);
        btnRow.add(Box.createHorizontalStrut(10));
        btnRow.add(btnClose);

        JPanel inputPanel = new JPanel(new BorderLayout(4, 4));
        inputPanel.setBorder(new EmptyBorder(8, 12, 4, 12));
        inputPanel.add(lbl,      BorderLayout.NORTH);
        inputPanel.add(sigField, BorderLayout.CENTER);
        inputPanel.add(btnRow,   BorderLayout.SOUTH);

        // ── Results area ──────────────────────────────────────────────────
        JTextArea resultArea = new JTextArea(12, 62);
        resultArea.setEditable(false);
        resultArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        JScrollPane scroll = new JScrollPane(resultArea);
        scroll.setBorder(new CompoundBorder(
                new EmptyBorder(0, 12, 4, 12),
                new TitledBorder("Results  (double-click a line to navigate)")));

        // ── Status bar ────────────────────────────────────────────────────
        JLabel statusBar = new JLabel(" Ready.");
        statusBar.setFont(statusBar.getFont().deriveFont(Font.PLAIN, 11f));
        statusBar.setBorder(new CompoundBorder(
                new MatteBorder(1, 0, 0, 0,
                        UIManager.getColor("Separator.foreground") != null
                                ? UIManager.getColor("Separator.foreground") : Color.GRAY),
                new EmptyBorder(3, 10, 3, 10)));

        // ── Root layout ───────────────────────────────────────────────────
        JPanel root = new JPanel(new BorderLayout());
        root.add(toolbar,    BorderLayout.NORTH);
        root.add(inputPanel, BorderLayout.CENTER); // inputPanel stretches
        // Wrap center+scroll together
        JPanel center = new JPanel(new BorderLayout());
        center.add(inputPanel, BorderLayout.NORTH);
        center.add(scroll,     BorderLayout.CENTER);
        root.add(center,    BorderLayout.CENTER);
        root.add(statusBar, BorderLayout.SOUTH);

        frame.setContentPane(root);
        frame.pack();
        frame.setMinimumSize(new Dimension(560, 380));
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
        frame.getRootPane().setDefaultButton(btnFind);
        sigField.requestFocus();

        // ── Double-click result line → navigate ───────────────────────────
        resultArea.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() != 2) return;
                try {
                    int line = resultArea.getLineOfOffset(
                            resultArea.viewToModel2D(e.getPoint()));
                    int start = resultArea.getLineStartOffset(line);
                    int end   = resultArea.getLineEndOffset(line);
                    String text = resultArea.getText().substring(start, end).trim();
                    // Line format: "  [N]  <hex-address>  (+0x...)"
                    for (String tok : text.split("\\s+")) {
                        if (tok.matches("[0-9a-fA-F]{6,16}")) {
                            Address dest = currentProgram.getAddressFactory()
                                    .getDefaultAddressSpace().getAddress(tok);
                            goTo(dest);
                            break;
                        }
                    }
                } catch (Exception ignored) {}
            }
        });

        // ── Search logic ──────────────────────────────────────────────────
        Runnable doFind = () -> runAsync(() -> {
            String raw = sigField.getText().trim();
            if (raw.isEmpty()) return;

            SwingUtilities.invokeLater(() -> {
                resultArea.setText("");
                statusBar.setText(" Searching…");
                btnFind.setEnabled(false);
            });

            try {
                String idaFlat = autoDetect(raw);
                if (idaFlat == null || idaFlat.isBlank()) {
                    SwingUtilities.invokeLater(() -> {
                        resultArea.setText("Could not parse signature format.\n");
                        statusBar.setText(" Parse error.");
                        btnFind.setEnabled(true);
                    });
                    return;
                }

                println("[SigMaker] Searching: " + idaFlat);
                List<Address> hits = findAll(idaFlat);
                long base = currentProgram.getImageBase().getOffset();

                StringBuilder sb = new StringBuilder();
                if (hits.isEmpty()) {
                    sb.append("No matches found.\n");
                    println("[SigMaker] No matches.");
                } else {
                    sb.append(hits.size()).append(" match(es):\n\n");
                    for (int i = 0; i < hits.size(); i++) {
                        Address a = hits.get(i);
                        sb.append(String.format("  [%d]  %s  (+0x%s)\n",
                                i + 1, a, Long.toHexString(a.getOffset() - base)));
                        println("[SigMaker] Match " + (i + 1) + ": " + a);
                    }
                }

                final String text   = sb.toString();
                final String status = hits.isEmpty()
                        ? " No matches found."
                        : " " + hits.size() + " match(es) — double-click a line to navigate.";

                SwingUtilities.invokeLater(() -> {
                    resultArea.setText(text);
                    resultArea.setCaretPosition(0);
                    statusBar.setText(status);
                    btnFind.setEnabled(true);
                });

            } catch (CancelledException ex) {
                SwingUtilities.invokeLater(() -> {
                    resultArea.setText("Cancelled.\n");
                    statusBar.setText(" Cancelled.");
                    btnFind.setEnabled(true);
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    resultArea.setText("Error: " + ex.getMessage() + "\n");
                    statusBar.setText(" Error.");
                    btnFind.setEnabled(true);
                });
            }
        });

        sigField.addActionListener(e -> doFind.run());
        btnFind .addActionListener(e -> doFind.run());

        btnClear.addActionListener(e -> {
            sigField.setText("");
            resultArea.setText("");
            statusBar.setText(" Ready.");
            sigField.requestFocus();
        });

        btnClose.addActionListener(e -> {
            frame.dispose();
            s_searchFrame = null;
        });

        // ESC closes the window
        frame.getRootPane().registerKeyboardAction(
                e -> { frame.dispose(); s_searchFrame = null; },
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_IN_FOCUSED_WINDOW);
    }

    // =========================================================================
    // EXECUTE ACTION
    // =========================================================================
    private void executeAction() {
        try {
            if (S_ACTION == 3) {
                SwingUtilities.invokeLater(this::showSearchDialog);
                return;
            }
            Address addr = resolveAddress();
            if (addr == null) {
                printerr("[SigMaker] Could not resolve a valid code address from current location.");
                return;
            }
            switch (S_ACTION) {
                case 0: doCreateSig(addr); break;
                case 1: doXRefSig(addr);   break;
                case 2: doCopyCode(addr);  break;
            }
        } catch (Exception e) {
            printerr("[SigMaker] Error: " + e.getMessage());
        }
    }

    private Address resolveAddress() {
        if (currentLocation == null) return null;
        Address addr = currentLocation.getAddress();
        if (addr == null) return null;

        if (currentProgram.getListing().getInstructionAt(addr) != null) return addr;

        Instruction containing = currentProgram.getListing().getInstructionContaining(addr);
        if (containing != null) return containing.getAddress();

        Function fn = currentProgram.getFunctionManager().getFunctionContaining(addr);
        if (fn != null) {
            println("[SigMaker] Cursor is in decompiler/non-listing view — using function entry: "
                    + fn.getEntryPoint());
            return fn.getEntryPoint();
        }

        Instruction next = currentProgram.getListing().getInstructionAfter(addr);
        if (next != null) return next.getAddress();

        return null;
    }

    // =========================================================================
    // ACTIONS
    // =========================================================================
    private void doCreateSig(Address start) throws Exception {
        println("[SigMaker] Creating signature at " + start + " ...");
        List<SigByte> sig = buildSig(start);
        if (sig == null) {
            println("[SigMaker] ERROR: Could not build a unique signature. Try increasing max length or changing operand options.");
            return;
        }
        outputSig(sig, "Signature @ " + start);
    }

    private void doXRefSig(Address target) throws Exception {
        println("[SigMaker] Finding XREF signatures to " + target + " ...");
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(target);
        List<SigEntry> results = new ArrayList<>();
        while (refs.hasNext()) {
            Reference ref = refs.next();
            Address from = ref.getFromAddress();
            MemoryBlock blk = currentProgram.getMemory().getBlock(from);
            if (blk == null || !blk.isInitialized() || !blk.isExecute()) continue;
            List<SigByte> sig = buildSig(from);
            if (sig != null) results.add(new SigEntry(sig, from));
        }
        if (results.isEmpty()) {
            println("[SigMaker] No unique XREF signatures found.");
            return;
        }
        results.sort(Comparator.comparingInt(s -> s.sig.size()));
        println("[SigMaker] Found " + results.size() + " XREF signature(s). Showing top 5:");
        int top = Math.min(5, results.size());
        for (int i = 0; i < top; i++) {
            println("--- XREF #" + (i + 1) + " from " + results.get(i).address + " ---");
            outputSig(results.get(i).sig, "XREF from " + results.get(i).address);
        }
    }

    private void doCopyCode(Address addr) throws Exception {
        Instruction instr = currentProgram.getListing().getInstructionAt(addr);
        if (instr == null) {
            println("[SigMaker] No instruction at cursor.");
            return;
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : instr.getBytes()) {
            if (sb.length() > 0) sb.append(' ');
            sb.append(String.format("%02X", b & 0xFF));
        }
        clip(sb.toString());
        println("[SigMaker] Copied: " + sb);
    }

    private static final class SigEntry {
        final List<SigByte> sig;
        final Address address;
        SigEntry(List<SigByte> s, Address a) { sig = s; address = a; }
    }

    // =========================================================================
    // CORE SIG BUILDER
    // =========================================================================
    private static final int MAX_SIG_BYTES = 1000;

    private List<SigByte> buildSig(Address start) throws Exception {
        Memory   mem     = currentProgram.getMemory();
        Listing  lst     = currentProgram.getListing();
        Function startFn = currentProgram.getFunctionManager().getFunctionContaining(start);
        List<SigByte> sig = new ArrayList<>();
        Address cur = start;

        while (sig.size() < MAX_SIG_BYTES) {
            if (!mem.contains(cur)) break;
            if (!S_CONTINUE_SCOPE && startFn != null) {
                Function curFn = currentProgram.getFunctionManager().getFunctionContaining(cur);
                if (curFn != null && !curFn.equals(startFn)) break;
            }
            Instruction instr = lst.getInstructionAt(cur);
            if (instr != null) {
                byte[]    bytes = instr.getBytes();
                boolean[] wc    = wildcardMask(instr);
                for (int i = 0; i < bytes.length; i++) sig.add(new SigByte(bytes[i], wc[i]));
                cur = cur.add(bytes.length);
            } else {
                byte    b     = mem.getByte(cur);
                boolean reloc = currentProgram.getRelocationTable().hasRelocation(cur);
                sig.add(new SigByte(b, reloc));
                cur = cur.add(1);
            }
            if (countMatches(sig) == 1) return sig;
        }
        return null;
    }

    private boolean[] wildcardMask(Instruction instr) {
        int       len = instr.getLength();
        boolean[] wc  = new boolean[len];

        for (int i = 0; i < len; i++) {
            try {
                if (currentProgram.getRelocationTable().hasRelocation(instr.getAddress().add(i)))
                    wc[i] = true;
            } catch (Exception ignored) {}
        }

        if (!S_WC_OPERANDS) return wc;

        boolean isFlow = instr.getFlowType().isJump() || instr.getFlowType().isCall();
        if (S_OP_JUMPS && instr.getFlowType().isJump()) wildcardFlowBytes(instr, wc);
        if (S_OP_CALLS && instr.getFlowType().isCall()) wildcardFlowBytes(instr, wc);

        for (int op = 0; op < instr.getNumOperands(); op++) {
            if (isFlow) continue;
            if (shouldWcOperand(instr, op)) wildcardOpBytes(instr, op, wc);
        }
        return wc;
    }

    private void wildcardFlowBytes(Instruction instr, boolean[] wc) {
        try {
            byte[] bytes = instr.getBytes();
            if (bytes.length < 2) return;
            int b0 = bytes[0] & 0xFF;
            if (b0 == 0xE8 || b0 == 0xE9) {
                for (int i = 1; i < Math.min(5, wc.length); i++) wc[i] = true;
            } else if (b0 == 0xEB || (b0 >= 0x70 && b0 <= 0x7F)) {
                if (wc.length >= 2) wc[1] = true;
            } else if (b0 == 0x0F && bytes.length >= 2 && (bytes[1] & 0xF0) == 0x80) {
                for (int i = 2; i < Math.min(6, wc.length); i++) wc[i] = true;
            } else if (b0 == 0xFF && bytes.length >= 2) {
                int mod = (bytes[1] & 0xC0) >> 6;
                int reg = (bytes[1] & 0x38) >> 3;
                if (reg == 2 || reg == 4) {
                    if (mod == 1 && wc.length >= 3) wc[2] = true;
                    if (mod == 2) for (int i = 2; i < Math.min(6, wc.length); i++) wc[i] = true;
                }
            }
        } catch (Exception ignored) {}
    }

    private boolean shouldWcOperand(Instruction instr, int opIdx) {
        Object[]    objs = instr.getOpObjects(opIdx);
        Reference[] refs = instr.getOperandReferences(opIdx);

        boolean hasScalar  = false;
        boolean hasAddress = false;
        long    scalarVal  = 0;
        int     scalarBits = 0;

        for (Object o : objs) {
            if (o instanceof Scalar) {
                hasScalar  = true;
                scalarVal  = ((Scalar) o).getUnsignedValue();
                scalarBits = ((Scalar) o).bitLength();
            } else if (o instanceof Address) {
                hasAddress = true;
            }
        }

        if (!hasScalar && !hasAddress && refs.length == 0) return false;

        for (Reference ref : refs) {
            Address to = ref.getToAddress();
            if (to == null) continue;
            if (to.isExternalAddress()) return true;
            MemoryBlock blk = currentProgram.getMemory().getBlock(to);
            if (blk == null) continue;
            if (S_OP_MEMORY && !blk.isExecute()) return true;
            if (S_OP_DIRECT &&  blk.isExecute()) return true;
        }

        if (hasScalar && refs.length == 0) {
            String mnem = instr.getMnemonicString().toUpperCase();
            boolean isMemInsn =
                mnem.startsWith("MOV")  || mnem.startsWith("LEA")  ||
                mnem.startsWith("ADD")  || mnem.startsWith("SUB")  ||
                mnem.startsWith("CMP")  || mnem.startsWith("AND")  ||
                mnem.startsWith("OR")   || mnem.startsWith("XOR")  ||
                mnem.startsWith("TEST") || mnem.startsWith("IMUL") ||
                mnem.startsWith("PUSH") || mnem.startsWith("POP")  ||
                mnem.startsWith("INC")  || mnem.startsWith("DEC");
            if (isMemInsn) {
                if (S_OP_DISPLACEMENT) return true;
            } else {
                if (S_OP_IMMEDIATE && scalarBits > 8) return true;
            }
        }

        if (S_OP_DIRECT && hasAddress && refs.length == 0) return true;
        return false;
    }

    private void wildcardOpBytes(Instruction instr, int opIdx, boolean[] wc) {
        try {
            byte[]   bytes = instr.getBytes();
            Object[] objs  = instr.getOpObjects(opIdx);
            for (Object o : objs) {
                long val = 0;
                if (o instanceof Scalar)        val = ((Scalar) o).getUnsignedValue();
                else if (o instanceof Address)  val = ((Address) o).getOffset();
                else continue;
                for (int size : new int[]{8, 4, 2, 1}) maskLE(wc, bytes, val, size);
            }
            for (Reference ref : instr.getOperandReferences(opIdx)) {
                Address to = ref.getToAddress();
                if (to == null) continue;
                long target   = to.getOffset();
                long instrEnd = instr.getAddress().getOffset() + bytes.length;
                long disp     = target - instrEnd;
                for (int size : new int[]{4, 2, 1}) maskLE(wc, bytes, disp, size);
                for (int size : new int[]{8, 4, 1}) maskLE(wc, bytes, target, size);
            }
        } catch (Exception ignored) {}
    }

    private void maskLE(boolean[] wc, byte[] bytes, long val, int size) {
        if (size < 1 || size > bytes.length || size > 8) return;
        for (int i = 0; i <= bytes.length - size; i++) {
            if (i == 0 && size == 1) continue;
            long cur = 0;
            for (int k = 0; k < size; k++) cur |= ((long)(bytes[i + k] & 0xFF)) << (k * 8);
            long mask = (size >= 8) ? -1L : ((1L << (size * 8)) - 1L);
            if ((cur & mask) == (val & mask)) {
                for (int k = 0; k < size; k++) wc[i + k] = true;
            }
        }
    }

    // =========================================================================
    // MATCH COUNTING / SEARCH
    // =========================================================================
    private int countMatches(List<SigByte> sig) throws Exception {
        byte[] pat = new byte[sig.size()];
        byte[] msk = new byte[sig.size()];
        for (int i = 0; i < sig.size(); i++) {
            pat[i] = sig.get(i).value;
            msk[i] = sig.get(i).wildcard ? 0 : (byte) 0xFF;
        }
        Memory  mem = currentProgram.getMemory();
        Address lo  = currentProgram.getMinAddress();
        Address hi  = currentProgram.getMaxAddress();
        Address f1  = mem.findBytes(lo, hi, pat, msk, true, TaskMonitor.DUMMY);
        if (f1 == null) return 0;
        Address f2  = mem.findBytes(f1.add(1), hi, pat, msk, true, TaskMonitor.DUMMY);
        return f2 == null ? 1 : 2;
    }

    private List<Address> findAll(String idaFlat) throws Exception {
        byte[][] pm = parseSig(idaFlat);
        if (pm == null) return Collections.emptyList();
        Memory mem = currentProgram.getMemory();
        List<Address> out = new ArrayList<>();
        Address cur = currentProgram.getMinAddress();
        Address hi  = currentProgram.getMaxAddress();
        while (cur != null) {
            cur = mem.findBytes(cur, hi, pm[0], pm[1], true, TaskMonitor.DUMMY);
            if (cur == null) break;
            out.add(cur);
            try { cur = cur.add(1); } catch (Exception e) { break; }
        }
        return out;
    }

    private byte[][] parseSig(String flat) {
        if (flat == null || flat.isBlank()) return null;
        String[] parts = flat.trim().split("\\s+");
        byte[] b = new byte[parts.length];
        byte[] m = new byte[parts.length];
        for (int i = 0; i < parts.length; i++) {
            if (parts[i].equals("?") || parts[i].equals("??")) {
                b[i] = 0; m[i] = 0;
            } else {
                try {
                    b[i] = (byte) Integer.parseInt(parts[i], 16);
                    m[i] = (byte) 0xFF;
                } catch (NumberFormatException e) { return null; }
            }
        }
        return new byte[][]{b, m};
    }

    // =========================================================================
    // FORMAT DETECTION + CONVERTERS
    // =========================================================================
    private String autoDetect(String raw) {
        raw = raw.trim();
        if (raw.contains("\\x"))                        return parseCByteArray(raw);
        if (raw.startsWith("0x") || raw.contains(",")) return parseCRawBytes(raw);
        return raw.replaceAll("\\?\\?", "?");
    }

    private String parseCByteArray(String raw) {
        String bytesPart = raw, maskPart = null;
        int sep = raw.indexOf("  ");
        if (sep < 0) sep = raw.lastIndexOf(' ');
        if (sep > 0) {
            String candidate = raw.substring(sep).trim();
            if (candidate.matches("[x?]+")) {
                bytesPart = raw.substring(0, sep).trim();
                maskPart  = candidate;
            }
        }
        List<String> toks = new ArrayList<>();
        for (String chunk : bytesPart.split("\\\\x")) {
            if (chunk.isEmpty()) continue;
            String s = chunk;
            while (s.length() >= 2) { toks.add(s.substring(0, 2).toUpperCase()); s = s.substring(2); }
        }
        if (maskPart != null)
            for (int i = 0; i < Math.min(maskPart.length(), toks.size()); i++)
                if (maskPart.charAt(i) == '?') toks.set(i, "?");
        return String.join(" ", toks);
    }

    private String parseCRawBytes(String raw) {
        String bytesPart = raw, bitmask = null;
        int bi = raw.indexOf("0b");
        if (bi > 0) {
            bytesPart = raw.substring(0, bi).replaceAll(",$", "").trim();
            bitmask   = raw.substring(bi + 2).trim();
        }
        List<String> toks = new ArrayList<>();
        for (String tok : bytesPart.split("[,\\s]+")) {
            tok = tok.trim();
            if (tok.isEmpty()) continue;
            toks.add(tok.startsWith("0x") || tok.startsWith("0X")
                    ? tok.substring(2).toUpperCase() : tok.toUpperCase());
        }
        if (bitmask != null)
            for (int i = 0; i < Math.min(bitmask.length(), toks.size()); i++)
                if (bitmask.charAt(i) == '0') toks.set(i, "?");
        return String.join(" ", toks);
    }

    private void outputSig(List<SigByte> sig, String label) {
        String ida  = toIDA(sig);
        String x64  = toX64(sig);
        String cArr = toCArr(sig);
        String cRaw = toCRaw(sig);
        String[] cArrParts = cArr.split("\n");

        println("");
        println("=== " + label + " ===");
        println("IDA Signature         : " + ida);
        println("x64Dbg Signature      : " + x64);
        println("C Byte Array          : " + cArrParts[0]);
        println("Mask                  : " + cArrParts[1]);
        println("C Raw Bytes + bitmask : " + cRaw);
        println("Length : " + sig.size() + " bytes");

        String toCopy;
        switch (S_FORMAT) {
            case 1:  toCopy = x64;  break;
            case 2:  toCopy = cArr; break;
            case 3:  toCopy = cRaw; break;
            default: toCopy = ida;  break;
        }
        clip(toCopy);
        println(">> Copied to clipboard (" + formatName() + ").");
    }

    private String formatName() {
        switch (S_FORMAT) {
            case 1:  return "x64Dbg";
            case 2:  return "C Byte Array";
            case 3:  return "C Raw Bytes";
            default: return "IDA";
        }
    }

    private String toIDA(List<SigByte> s) {
        StringBuilder sb = new StringBuilder();
        for (SigByte b : s) {
            if (sb.length() > 0) sb.append(' ');
            sb.append(b.wildcard ? "?" : String.format("%02X", b.value & 0xFF));
        }
        return sb.toString();
    }

    private String toX64(List<SigByte> s) {
        StringBuilder sb = new StringBuilder();
        for (SigByte b : s) {
            if (sb.length() > 0) sb.append(' ');
            sb.append(b.wildcard ? "??" : String.format("%02X", b.value & 0xFF));
        }
        return sb.toString();
    }

    private String toCArr(List<SigByte> s) {
        StringBuilder bytes = new StringBuilder();
        StringBuilder mask  = new StringBuilder();
        for (SigByte b : s) {
            bytes.append(String.format("\\x%02X", b.value & 0xFF));
            mask.append(b.wildcard ? '?' : 'x');
        }
        return bytes.toString() + "\n" + mask.toString();
    }

    private String toCRaw(List<SigByte> s) {
        StringBuilder bytes = new StringBuilder();
        StringBuilder bits  = new StringBuilder("0b");
        for (int i = 0; i < s.size(); i++) {
            if (i > 0) bytes.append(", ");
            bytes.append(String.format("0x%02X", s.get(i).value & 0xFF));
            bits.append(s.get(i).wildcard ? '0' : '1');
        }
        return bytes.toString() + " " + bits.toString();
    }

    // =========================================================================
    // UI HELPERS
    // =========================================================================
    private static JLabel sectionLabel(String text) {
        JLabel l = new JLabel(text);
        l.setAlignmentX(Component.LEFT_ALIGNMENT);
        return l;
    }

    private static JRadioButton radio(String text, ButtonGroup g) {
        JRadioButton r = new JRadioButton(text);
        g.add(r);
        return r;
    }

    private static JPanel bordered(JComponent... components) {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBorder(new CompoundBorder(
                BorderFactory.createEtchedBorder(),
                new EmptyBorder(6, 8, 6, 8)));
        for (JComponent c : components) {
            c.setAlignmentX(Component.LEFT_ALIGNMENT);
            p.add(c);
        }
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        return p;
    }

    private static int selectedIndex(JRadioButton[] btns) {
        for (int i = 0; i < btns.length; i++) if (btns[i].isSelected()) return i;
        return 0;
    }

    private void clip(String t) {
        try {
            StringSelection s = new StringSelection(t);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(s, s);
        } catch (Exception ignored) {}
    }

    private void runAsync(Runnable r) { new Thread(r, "SigMaker-Worker").start(); }
}
