
*********************************************************

  MsFontsFuzz: OpenType font format fuzzer for Windows

  By Oleksiuk Dmytro (aka Cr4sh)
  http://twitter.com/d_olex
  http://blog.cr4.sh
  mailto:cr4sh0@gmail.com
  
*********************************************************

USAGE:

  > MsFontsFuzz.exe <font_name> <font_file_path> [options]

... where <font_name> and <font_file_path> – Text name of the font and path to the .TTF/.OTF font file.

The [options] can be:

  --test – Just draw font characters and print file information without fuzzing.

  --text – String that will be drawn during fuzzing using the specified font. By default - ASCII ñcharacters string in range 20h – 7Fh.

  --noisy – Print detailed information about each fuzzing iteration.

  --fix-crcs – Fix invalid checksums in specified font file without fuzzing.
  
  
EXAMPLE:

See Release\BrushScriptStd_Fuzzing.bat - you can run this scenario to start fuzzing with the Brush Script Std Regular font.

This fuzzer helps me to find remote (client-side) DoS 0day vulnerability in Windows kernel, with invalid decoding of 0x0d byte in the Type 2 Charstring Format Glyph, that drops ATMFD.DLL code into the infinite loop.

PoC code: http://dl.dropbox.com/u/22903093/blog/CFF_Type-1_0x0d_expl/CFF_Type-1_0x0d_expl.rar

Detailed analysis (russian): http://blog.cr4.sh/2012/06/0day-windows.html



