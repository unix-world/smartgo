// JS-Script (UM): multiplex_test.js @ 2023-12-03 00:03:57 +0000
(function(){CodeMirror.defineMode("markdown_with_stex",function(){var e=CodeMirror.getMode({},"stex");var r=CodeMirror.getMode({},"markdown");var i={open:"$",close:"$",mode:e,delimStyle:"delim",innerStyle:"inner"};return CodeMirror.multiplexingMode(r,i)});var r=CodeMirror.getMode({},"markdown_with_stex");function e(e){test.mode(e,r,Array.prototype.slice.call(arguments,1),"multiplexing")}e("stexInsideMarkdown","[strong **Equation:**] [delim&delim-open $][inner&tag \\pi][delim&delim-close $]");CodeMirror.defineMode("identical_delim_multiplex",function(){return CodeMirror.multiplexingMode(CodeMirror.getMode({indentUnit:2},"javascript"),{open:"#",close:"#",mode:CodeMirror.getMode({},"markdown"),parseDelimiters:true,innerStyle:"q"})});var i=CodeMirror.getMode({},"identical_delim_multiplex");test.mode("identical_delimiters_with_parseDelimiters",i,["[keyword let] [def x] [operator =] [q #foo][q&em *bar*][q #];"],"multiplexing")})();
// #END