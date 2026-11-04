import AppKit
import Foundation

let output = URL(fileURLWithPath:CommandLine.arguments[1],isDirectory:true)
try FileManager.default.createDirectory(at:output,withIntermediateDirectories:true)
for (name,size) in [("icon_16x16",16),("icon_16x16@2x",32),("icon_32x32",32),("icon_32x32@2x",64),("icon_128x128",128),("icon_128x128@2x",256),("icon_256x256",256),("icon_256x256@2x",512),("icon_512x512",512),("icon_512x512@2x",1024)] {
    let rep = NSBitmapImageRep(bitmapDataPlanes:nil,pixelsWide:size,pixelsHigh:size,bitsPerSample:8,samplesPerPixel:4,hasAlpha:true,isPlanar:false,colorSpaceName:.deviceRGB,bytesPerRow:0,bitsPerPixel:0)!
    NSGraphicsContext.saveGraphicsState(); NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep:rep)
    NSGraphicsContext.current?.cgContext.scaleBy(x:CGFloat(size)/1024,y:CGFloat(size)/1024)
    let yellow = NSColor(calibratedRed:0.98,green:0.84,blue:0.19,alpha:1)
    yellow.setFill(); NSBezierPath(roundedRect:NSRect(x:32,y:32,width:960,height:960),xRadius:212,yRadius:212).fill()
    NSColor(calibratedRed:0.13,green:0.13,blue:0.12,alpha:1).setFill()
    NSBezierPath(roundedRect:NSRect(x:222,y:300,width:580,height:450),xRadius:148,yRadius:148).fill()
    let tail = NSBezierPath(); tail.move(to:NSPoint(x:320,y:345));tail.line(to:NSPoint(x:320,y:184));tail.line(to:NSPoint(x:494,y:345));tail.close();tail.fill()
    yellow.setStroke();let minus = NSBezierPath();minus.lineWidth = 54;minus.lineCapStyle = .round;minus.move(to:NSPoint(x:390,y:520));minus.line(to:NSPoint(x:634,y:520));minus.stroke()
    NSGraphicsContext.restoreGraphicsState()
    try rep.representation(using:.png,properties:[:])!.write(to:output.appendingPathComponent(name+".png"))
}
