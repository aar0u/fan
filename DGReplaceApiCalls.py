from com.pnfsoftware.jeb.core.units.code.android.ir import AbstractDOptimizer, IDVisitor

'''
This JEB's dexdec IR optimizer will attempt to resolve artificial Android library invocations added
by DexGuard (version > spring 2021), designed to hamper the string auto-decryption process.
TODO: DexGuard uses many utility methods to block JEB's emulator; add support for more of them.

This Python plugin is executed during the decompilation pipeline of a method.
Needs JEB 4.2 or above.

Example:
 
  private static String a(String str, int key) {
    StringBuilder out = new StringBuilder();
    for(int i = 0; i < str.length(); i++) {
      char c = (char)(str.charAt(i) - key + 0xFF);
      out.append(c);
    }
    return out.toString();
  }

  // adapted and simplified from a sample protected by DexGuard, collected in June 2021
  public String get() {
    int key = 0x100 - Color.red(0);   // 0x100 - 0 = 0x100, the key value
    return a("ifmmp", key);           // would return "hello""
  }

Problem: Here, JEB cannot auto-decrypt and inline a(), because of the Color.red(0) invocation.
Solution: This IR plugin finds such calls, evaluates them, and replaces the IR by a constant, thereby allowing
further optimizers in the decompilation pipeline to proceed and eventually auto-decrypt and decompile this method to:

  public String get() {
    return "hello";
  }

How to use:
- Drop this file in your JEB's coreplugins/python/ sub-directory
- Make sure to have the setting `.LoadPythonPlugins = true` in your JEB's bin/jeb-engines.cfg file

For additional information regarding dexdec IR optimizer plugins, refer to:
- the Manual (www.pnfsoftware.com/jeb/manual)
- the API documentation: https://www.pnfsoftware.com/jeb/apidoc/reference/com/pnfsoftware/jeb/core/units/code/android/ir/package-summary.html
'''

class DGReplaceApiCalls(AbstractDOptimizer):  # note that we extend AbstractDOptimizer for convenience, instead of implementing IDOptimizer from scratch
  def perform(self):
    # create our instruction visitor
    vis = AndroidUtilityVisitor(self.ctx)
    # visit all the instructions of the IR CFG
    for insn in self.cfg.instructions():
      insn.visitInstruction(vis)
    # return the count of replacements
    return vis.cnt

class AndroidUtilityVisitor(IDVisitor):
  def __init__(self, ctx):
    self.ctx = ctx
    self.cnt = 0

  def process(self, e, parent, results):
    repl = None

    if e.isCallInfo():
      sig = e.getMethodSignature()

      # Color.red(integer_value)
      if sig == 'Landroid/graphics/Color;->red(I)I' and e.getArgument(0).isImm():
        color = e.getArgument(0).toLong()
        # extract the red value
        redval = (color >> 16) & 0xFF
        # replace the IDCallInfo by an IDImm
        repl = self.ctx.getGlobalContext().createInt(redval)

      # TextUtils.getOffsetBefore("", 0)
      elif sig == 'Landroid/text/TextUtils;->getOffsetBefore(Ljava/lang/CharSequence;I)I' and e.getArgument(0).isImm() and e.getArgument(1).isImm():
        buf = e.getArgument(0).getStringValue(self.ctx.getGlobalContext())
        val = e.getArgument(1).toLong()
        if buf == '' and val == 0:
          repl = self.ctx.getGlobalContext().createInt(0)

      # Long.compare(xxx, 0)
      elif sig == 'Ljava/lang/Long;->compare(JJ)I' and e.getArgument(1).isImm() and e.getArgument(1).asImm().isZeroEquivalent():
        val0 = None
        arg0 = e.getArgument(0)
        if arg0.isCallInfo():
          sig2 = arg0.getMethodSignature()
          if sig2 == 'Landroid/os/Process;->getElapsedCpuTime()J':
            # elapsed time always >0, value does not matter since we are comparing against 0
            val0 = 1
        if val0 != None:
          if val0 > 0:
            r = 1
          elif val0 < 0:
            r = -1
          else:
            r = 0
          repl = self.ctx.getGlobalContext().createInt(r)

      # ViewConfiguration.getFadingEdgeLength()
      elif sig == 'Landroid/view/ViewConfiguration;->getFadingEdgeLength()I':
        # always a small positive integer, normally set to FADING_EDGE_LENGTH (12)
        repl = self.ctx.getGlobalContext().createInt(12)

    if repl != None and parent.replaceSubExpression(e, repl):
      # success (this visitor is pre-order, we need to report the replaced node)
      results.setReplacedNode(repl)
      self.cnt += 1
