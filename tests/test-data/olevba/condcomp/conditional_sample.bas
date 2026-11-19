Attribute VB_Name = "ConditionalSample"
Sub AutoOpen()
    #If VBA7 Then
        #If Win64 Then
            Shell "payload_x64.exe"
        #Else
            Shell "payload_x86.exe"
        #End If
    #Else
        Kill "C:\\legacy.tmp"
    #End If
End Sub

Sub Helper()
    #If Mac Then
        MacScript "do shell script"
    #End If
End Sub
