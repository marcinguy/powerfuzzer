# Powerfuzzer
# Copyright (C) 2008 Marcin Kozlowski

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  US

import wx
import wx.richtext as rt
import icons


class ReportFrame(wx.Frame):
    def __init__(self, *args, **kw):
        wx.Frame.__init__(self, *args, **kw)

        self.MakeMenuBar()
        self.MakeToolBar()
        self.CreateStatusBar()
        self.SetStatusText("")

        self.rtc = rt.RichTextCtrl(self, style=wx.VSCROLL|wx.HSCROLL|wx.NO_BORDER);
        wx.CallAfter(self.rtc.SetFocus)


	self.rtc.Freeze()
        self.rtc.BeginSuppressUndo()

        self.rtc.BeginParagraphSpacing(0, 20)

        self.rtc.BeginAlignment(rt.TEXT_ALIGNMENT_CENTRE)
        self.rtc.BeginBold()

        self.rtc.BeginFontSize(14)
        self.rtc.WriteText("Findings summary")
        self.rtc.EndFontSize()
 	self.rtc.EndAlignment()
	self.rtc.EndBold()
	self.rtc.Newline()
	self.rtc.Newline()
	self.rtc.Newline()

        self.rtc.EndSuppressUndo()
        self.rtc.Thaw()

        
    def addFindings(self,data):

	self.rtc.Freeze()
        self.rtc.BeginSuppressUndo()
        self.rtc.BeginAlignment(rt.TEXT_ALIGNMENT_LEFT)        
	self.rtc.BeginTextColour((0, 0, 255))
      	for line in data:   
	   self.rtc.WriteText(line)
	   self.rtc.Newline()
        
	self.rtc.EndTextColour()
	self.rtc.EndAlignment() 
        self.rtc.EndSuppressUndo()
        self.rtc.Thaw()
       

    def OnURL(self, evt):
        wx.MessageBox(evt.GetString(), "URL Clicked")
        

    def OnFileOpen(self, evt):
        # This gives us a string suitable for the file dialog based on
        # the file handlers that are loaded
        wildcard, types = rt.RichTextBuffer.GetExtWildcard(save=False)
        dlg = wx.FileDialog(self, "Choose a filename",
                            wildcard=wildcard,
                            style=wx.OPEN)
        if dlg.ShowModal() == wx.ID_OK:
            path = dlg.GetPath()
            if path:
                fileType = types[dlg.GetFilterIndex()]
                self.rtc.LoadFile(path, fileType)
        dlg.Destroy()

        
    def OnFileSave(self, evt):
        if not self.rtc.GetFilename():
            self.OnFileSaveAs(evt)
            return
        self.rtc.SaveFile()

        
    def OnFileSaveAs(self, evt):
        wildcard, types = rt.RichTextBuffer.GetExtWildcard(save=True)

        dlg = wx.FileDialog(self, "Choose a filename",
                            wildcard=wildcard,
                            style=wx.SAVE)
        if dlg.ShowModal() == wx.ID_OK:
            path = dlg.GetPath()
            if path:
                fileType = types[dlg.GetFilterIndex()]
                ext = rt.RichTextBuffer.FindHandlerByType(fileType).GetExtension()
                if not path.endswith(ext):
                    path += '.' + ext
                self.rtc.SaveFile(path, fileType)
        dlg.Destroy()
        
                
    def OnFileViewHTML(self, evt):
        # Get an instance of the html file handler, use it to save the
        # document to a StringIO stream, and then display the
        # resulting html text in a dialog with a HtmlWindow.
        handler = rt.RichTextHTMLHandler()
        handler.SetFlags(rt.RICHTEXT_HANDLER_SAVE_IMAGES_TO_MEMORY)
        handler.SetFontSizeMapping([7,9,11,12,14,22,100])

        import cStringIO
        stream = cStringIO.StringIO()
        if not handler.SaveStream(self.rtc.GetBuffer(), stream):
            return

        import wx.html
        dlg = wx.Dialog(self, title="HTML", style=wx.DEFAULT_DIALOG_STYLE|wx.RESIZE_BORDER)
        html = wx.html.HtmlWindow(dlg, size=(500,400), style=wx.BORDER_SUNKEN)
        html.SetPage(stream.getvalue())
        btn = wx.Button(dlg, wx.ID_CANCEL)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(html, 1, wx.ALL|wx.EXPAND, 5)
        sizer.Add(btn, 0, wx.ALL|wx.CENTER, 10)
        dlg.SetSizer(sizer)
        sizer.Fit(dlg)

        dlg.ShowModal()

        handler.DeleteTemporaryImages()
        

    
    def OnFileExit(self, evt):
        self.Close(True)

      
    def OnBold(self, evt):
        self.rtc.ApplyBoldToSelection()
        
    def OnItalic(self, evt): 
        self.rtc.ApplyItalicToSelection()
        
    def OnUnderline(self, evt):
        self.rtc.ApplyUnderlineToSelection()
        
    def OnAlignLeft(self, evt):
        self.rtc.ApplyAlignmentToSelection(rt.TEXT_ALIGNMENT_LEFT)
        
    def OnAlignRight(self, evt):
        self.rtc.ApplyAlignmentToSelection(rt.TEXT_ALIGNMENT_RIGHT)
        
    def OnAlignCenter(self, evt):
        self.rtc.ApplyAlignmentToSelection(rt.TEXT_ALIGNMENT_CENTRE)
        
    def OnIndentMore(self, evt):
        attr = rt.TextAttrEx()
        attr.SetFlags(rt.TEXT_ATTR_LEFT_INDENT)
        ip = self.rtc.GetInsertionPoint()
        if self.rtc.GetStyle(ip, attr):
            r = rt.RichTextRange(ip, ip)
            if self.rtc.HasSelection():
                r = self.rtc.GetSelectionRange()

            attr.SetLeftIndent(attr.GetLeftIndent() + 100)
            attr.SetFlags(rt.TEXT_ATTR_LEFT_INDENT)
            self.rtc.SetStyle(r, attr)
       
        
    def OnIndentLess(self, evt):
        attr = rt.TextAttrEx()
        attr.SetFlags(rt.TEXT_ATTR_LEFT_INDENT)
        ip = self.rtc.GetInsertionPoint()
        if self.rtc.GetStyle(ip, attr):
            r = rt.RichTextRange(ip, ip)
            if self.rtc.HasSelection():
                r = self.rtc.GetSelectionRange()

        if attr.GetLeftIndent() >= 100:
            attr.SetLeftIndent(attr.GetLeftIndent() - 100)
            attr.SetFlags(rt.TEXT_ATTR_LEFT_INDENT)
            self.rtc.SetStyle(r, attr)

        
    def OnParagraphSpacingMore(self, evt):
        attr = rt.TextAttrEx()
        attr.SetFlags(rt.TEXT_ATTR_PARA_SPACING_AFTER)
        ip = self.rtc.GetInsertionPoint()
        if self.rtc.GetStyle(ip, attr):
            r = rt.RichTextRange(ip, ip)
            if self.rtc.HasSelection():
                r = self.rtc.GetSelectionRange()

            attr.SetParagraphSpacingAfter(attr.GetParagraphSpacingAfter() + 20);
            attr.SetFlags(rt.TEXT_ATTR_PARA_SPACING_AFTER)
            self.rtc.SetStyle(r, attr)

        
    def OnParagraphSpacingLess(self, evt):
        attr = rt.TextAttrEx()
        attr.SetFlags(rt.TEXT_ATTR_PARA_SPACING_AFTER)
        ip = self.rtc.GetInsertionPoint()
        if self.rtc.GetStyle(ip, attr):
            r = rt.RichTextRange(ip, ip)
            if self.rtc.HasSelection():
                r = self.rtc.GetSelectionRange()

            if attr.GetParagraphSpacingAfter() >= 20:
                attr.SetParagraphSpacingAfter(attr.GetParagraphSpacingAfter() - 20);
                attr.SetFlags(rt.TEXT_ATTR_PARA_SPACING_AFTER)
                self.rtc.SetStyle(r, attr)

        
    def OnLineSpacingSingle(self, evt): 
        attr = rt.TextAttrEx()
        attr.SetFlags(rt.TEXT_ATTR_LINE_SPACING)
        ip = self.rtc.GetInsertionPoint()
        if self.rtc.GetStyle(ip, attr):
            r = rt.RichTextRange(ip, ip)
            if self.rtc.HasSelection():
                r = self.rtc.GetSelectionRange()

            attr.SetFlags(rt.TEXT_ATTR_LINE_SPACING)
            attr.SetLineSpacing(10)
            self.rtc.SetStyle(r, attr)
 
                
    def OnLineSpacingHalf(self, evt):
        attr = rt.TextAttrEx()
        attr.SetFlags(rt.TEXT_ATTR_LINE_SPACING)
        ip = self.rtc.GetInsertionPoint()
        if self.rtc.GetStyle(ip, attr):
            r = rt.RichTextRange(ip, ip)
            if self.rtc.HasSelection():
                r = self.rtc.GetSelectionRange()

            attr.SetFlags(rt.TEXT_ATTR_LINE_SPACING)
            attr.SetLineSpacing(15)
            self.rtc.SetStyle(r, attr)

        
    def OnLineSpacingDouble(self, evt):
        attr = rt.TextAttrEx()
        attr.SetFlags(rt.TEXT_ATTR_LINE_SPACING)
        ip = self.rtc.GetInsertionPoint()
        if self.rtc.GetStyle(ip, attr):
            r = rt.RichTextRange(ip, ip)
            if self.rtc.HasSelection():
                r = self.rtc.GetSelectionRange()

            attr.SetFlags(rt.TEXT_ATTR_LINE_SPACING)
            attr.SetLineSpacing(20)
            self.rtc.SetStyle(r, attr)


    def OnFont(self, evt):
        if not self.rtc.HasSelection():
            return

        r = self.rtc.GetSelectionRange()
        fontData = wx.FontData()
        fontData.EnableEffects(False)
        attr = rt.TextAttrEx()
        attr.SetFlags(rt.TEXT_ATTR_FONT)
        if self.rtc.GetStyle(self.rtc.GetInsertionPoint(), attr):
            fontData.SetInitialFont(attr.GetFont())

        dlg = wx.FontDialog(self, fontData)
        if dlg.ShowModal() == wx.ID_OK:
            fontData = dlg.GetFontData()
            font = fontData.GetChosenFont()
            if font:
                attr.SetFlags(rt.TEXT_ATTR_FONT)
                attr.SetFont(font)
                self.rtc.SetStyle(r, attr)
        dlg.Destroy()


    def OnColour(self, evt):
        colourData = wx.ColourData()
        attr = rt.TextAttrEx()
        attr.SetFlags(rt.TEXT_ATTR_TEXT_COLOUR)
        if self.rtc.GetStyle(self.rtc.GetInsertionPoint(), attr):
            colourData.SetColour(attr.GetTextColour())

        dlg = wx.ColourDialog(self, colourData)
        if dlg.ShowModal() == wx.ID_OK:
            colourData = dlg.GetColourData()
            colour = colourData.GetColour()
            if colour:
                if not self.rtc.HasSelection():
                    self.rtc.BeginTextColour(colour)
                else:
                    r = self.rtc.GetSelectionRange()
                    attr.SetFlags(rt.TEXT_ATTR_TEXT_COLOUR)
                    attr.SetTextColour(colour)
                    self.rtc.SetStyle(r, attr)
        dlg.Destroy()
        


    def OnUpdateBold(self, evt):
        evt.Check(self.rtc.IsSelectionBold())
    
    def OnUpdateItalic(self, evt): 
        evt.Check(self.rtc.IsSelectionItalics())
    
    def OnUpdateUnderline(self, evt): 
        evt.Check(self.rtc.IsSelectionUnderlined())
    
    def OnUpdateAlignLeft(self, evt):
        evt.Check(self.rtc.IsSelectionAligned(rt.TEXT_ALIGNMENT_LEFT))
        
    def OnUpdateAlignCenter(self, evt):
        evt.Check(self.rtc.IsSelectionAligned(rt.TEXT_ALIGNMENT_CENTRE))
        
    def OnUpdateAlignRight(self, evt):
        evt.Check(self.rtc.IsSelectionAligned(rt.TEXT_ALIGNMENT_RIGHT))

    
    def ForwardEvent(self, evt):
        # The RichTextCtrl can handle menu and update events for undo,
        # redo, cut, copy, paste, delete, and select all, so just
        # forward the event to it.
        self.rtc.ProcessEvent(evt)


    def MakeMenuBar(self):
        def doBind(item, handler, updateUI=None):
            self.Bind(wx.EVT_MENU, handler, item)
            if updateUI is not None:
                self.Bind(wx.EVT_UPDATE_UI, updateUI, item)
            
        fileMenu = wx.Menu()
        doBind( fileMenu.Append(-1, "&Open\tCtrl+O", "Open a file"),
                self.OnFileOpen )
        doBind( fileMenu.Append(-1, "&Save\tCtrl+S", "Save a file"),
                self.OnFileSave )
        doBind( fileMenu.Append(-1, "&Save As...\tF12", "Save to a new file"),
                self.OnFileSaveAs )
        fileMenu.AppendSeparator()
        doBind( fileMenu.Append(-1, "&View as HTML", "View HTML"),
                self.OnFileViewHTML)
        fileMenu.AppendSeparator()
        doBind( fileMenu.Append(-1, "E&xit\tCtrl+Q", "Quit this program"),
                self.OnFileExit )
        
        editMenu = wx.Menu()
        doBind( editMenu.Append(wx.ID_UNDO, "&Undo\tCtrl+Z"),
                self.ForwardEvent, self.ForwardEvent)
        doBind( editMenu.Append(wx.ID_REDO, "&Redo\tCtrl+Y"),
                self.ForwardEvent, self.ForwardEvent )
        editMenu.AppendSeparator()
        doBind( editMenu.Append(wx.ID_CUT, "Cu&t\tCtrl+X"),
                self.ForwardEvent, self.ForwardEvent )
        doBind( editMenu.Append(wx.ID_COPY, "&Copy\tCtrl+C"),
                self.ForwardEvent, self.ForwardEvent)
        doBind( editMenu.Append(wx.ID_PASTE, "&Paste\tCtrl+V"),
                self.ForwardEvent, self.ForwardEvent)
        doBind( editMenu.Append(wx.ID_CLEAR, "&Delete\tDel"),
                self.ForwardEvent, self.ForwardEvent)
        editMenu.AppendSeparator()
        doBind( editMenu.Append(wx.ID_SELECTALL, "Select A&ll\tCtrl+A"),
                self.ForwardEvent, self.ForwardEvent )
        
        #doBind( editMenu.AppendSeparator(),  )
        #doBind( editMenu.Append(-1, "&Find...\tCtrl+F"),  )
        #doBind( editMenu.Append(-1, "&Replace...\tCtrl+R"),  )

        formatMenu = wx.Menu()
        doBind( formatMenu.AppendCheckItem(-1, "&Bold\tCtrl+B"),
                self.OnBold, self.OnUpdateBold)
        doBind( formatMenu.AppendCheckItem(-1, "&Italic\tCtrl+I"),
                self.OnItalic, self.OnUpdateItalic)
        doBind( formatMenu.AppendCheckItem(-1, "&Underline\tCtrl+U"),
                self.OnUnderline, self.OnUpdateUnderline)
        formatMenu.AppendSeparator()
        doBind( formatMenu.AppendCheckItem(-1, "L&eft Align"),
                self.OnAlignLeft, self.OnUpdateAlignLeft)
        doBind( formatMenu.AppendCheckItem(-1, "&Centre"),
                self.OnAlignCenter, self.OnUpdateAlignCenter)
        doBind( formatMenu.AppendCheckItem(-1, "&Right Align"),
                self.OnAlignRight, self.OnUpdateAlignRight)
        formatMenu.AppendSeparator()
        doBind( formatMenu.Append(-1, "Indent &More"), self.OnIndentMore)
        doBind( formatMenu.Append(-1, "Indent &Less"), self.OnIndentLess)
        formatMenu.AppendSeparator()
        doBind( formatMenu.Append(-1, "Increase Paragraph &Spacing"), self.OnParagraphSpacingMore)
        doBind( formatMenu.Append(-1, "Decrease &Paragraph Spacing"), self.OnParagraphSpacingLess)
        formatMenu.AppendSeparator()
        doBind( formatMenu.Append(-1, "Normal Line Spacing"), self.OnLineSpacingSingle)
        doBind( formatMenu.Append(-1, "1.5 Line Spacing"), self.OnLineSpacingHalf)
        doBind( formatMenu.Append(-1, "Double Line Spacing"), self.OnLineSpacingDouble)
        formatMenu.AppendSeparator()
        doBind( formatMenu.Append(-1, "&Font..."), self.OnFont)
        
        mb = wx.MenuBar()
        mb.Append(fileMenu, "&File")
        mb.Append(editMenu, "&Edit")
        mb.Append(formatMenu, "F&ormat")
        self.SetMenuBar(mb)


    def MakeToolBar(self):
        def doBind(item, handler, updateUI=None):
            self.Bind(wx.EVT_TOOL, handler, item)
            if updateUI is not None:
                self.Bind(wx.EVT_UPDATE_UI, updateUI, item)
        
        tbar = self.CreateToolBar()
        doBind( tbar.AddTool(-1, icons.get_rt_openBitmap(),
                            shortHelpString="Open"), self.OnFileOpen)
        doBind( tbar.AddTool(-1, icons.get_rt_saveBitmap(),
                            shortHelpString="Save"), self.OnFileSave)
        tbar.AddSeparator()
        doBind( tbar.AddTool(wx.ID_CUT, icons.get_rt_cutBitmap(),
                            shortHelpString="Cut"), self.ForwardEvent, self.ForwardEvent)
        doBind( tbar.AddTool(wx.ID_COPY, icons.get_rt_copyBitmap(),
                            shortHelpString="Copy"), self.ForwardEvent, self.ForwardEvent)
        doBind( tbar.AddTool(wx.ID_PASTE, icons.get_rt_pasteBitmap(),
                            shortHelpString="Paste"), self.ForwardEvent, self.ForwardEvent)
        tbar.AddSeparator()
        doBind( tbar.AddTool(wx.ID_UNDO, icons.get_rt_undoBitmap(),
                            shortHelpString="Undo"), self.ForwardEvent, self.ForwardEvent)
        doBind( tbar.AddTool(wx.ID_REDO, icons.get_rt_redoBitmap(),
                            shortHelpString="Redo"), self.ForwardEvent, self.ForwardEvent)
        tbar.AddSeparator()
        doBind( tbar.AddTool(-1, icons.get_rt_boldBitmap(), isToggle=True,
                            shortHelpString="Bold"), self.OnBold, self.OnUpdateBold)
        doBind( tbar.AddTool(-1, icons.get_rt_italicBitmap(), isToggle=True,
                            shortHelpString="Italic"), self.OnItalic, self.OnUpdateItalic)
        doBind( tbar.AddTool(-1, icons.get_rt_underlineBitmap(), isToggle=True,
                            shortHelpString="Underline"), self.OnUnderline, self.OnUpdateUnderline)
        tbar.AddSeparator()
        doBind( tbar.AddTool(-1, icons.get_rt_alignleftBitmap(), isToggle=True,
                            shortHelpString="Align Left"), self.OnAlignLeft, self.OnUpdateAlignLeft)
        doBind( tbar.AddTool(-1, icons.get_rt_centreBitmap(), isToggle=True,
                            shortHelpString="Center"), self.OnAlignCenter, self.OnUpdateAlignCenter)
        doBind( tbar.AddTool(-1, icons.get_rt_alignrightBitmap(), isToggle=True,
                            shortHelpString="Align Right"), self.OnAlignRight, self.OnUpdateAlignRight)
        tbar.AddSeparator()
        doBind( tbar.AddTool(-1, icons.get_rt_indentlessBitmap(),
                            shortHelpString="Indent Less"), self.OnIndentLess)
        doBind( tbar.AddTool(-1, icons.get_rt_indentmoreBitmap(),
                            shortHelpString="Indent More"), self.OnIndentMore)
        tbar.AddSeparator()
        doBind( tbar.AddTool(-1, icons.get_rt_fontBitmap(),
                            shortHelpString="Font"), self.OnFont)
        doBind( tbar.AddTool(-1, icons.get_rt_colourBitmap(),
                            shortHelpString="Font Colour"), self.OnColour)

        tbar.Realize()

       
