Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Create the form
$form = New-Object Windows.Forms.Form
$form.Text = "Bradley's Email Header Analyzer Tool v0.2"
$form.Size = New-Object Drawing.Size(800, 600)
$form.StartPosition = "CenterScreen"

# Header input box
$headerBox = New-Object Windows.Forms.TextBox
$headerBox.Multiline = $true
$headerBox.ScrollBars = "Vertical"
$headerBox.Size = New-Object Drawing.Size(760, 200)
$headerBox.Location = New-Object Drawing.Point(10, 10)
$form.Controls.Add($headerBox)

# Analyze button
$analyzeButton = New-Object Windows.Forms.Button
$analyzeButton.Text = "Analyze Headers"
$analyzeButton.Size = New-Object Drawing.Size(150, 30)
$analyzeButton.Location = New-Object Drawing.Point(10, 220)
$form.Controls.Add($analyzeButton)

# Output label
$outputBox = New-Object Windows.Forms.RichTextBox
$outputBox.Size = New-Object Drawing.Size(760, 300)
$outputBox.Location = New-Object Drawing.Point(10, 260)
$outputBox.ReadOnly = $true
$outputBox.BackColor = "Black"
$outputBox.ForeColor = "White"
$form.Controls.Add($outputBox)

# Analysis logic
$analyzeButton.Add_Click({
    $outputBox.Clear()
    $headers = $headerBox.Text
    $spamScore = 0
    $notes = @()

    # Extract values
    $from = [regex]::Match($headers, 'From:\s*"?(.+?)"?\s*<(.+?)>').Groups[2].Value.Trim()
    $returnPath = [regex]::Match($headers, "Return-Path:\s*<(.*?)>").Groups[1].Value.Trim()
    $subject = [regex]::Match($headers, "Subject:\s*(.+)").Groups[1].Value.Trim()

    $fromDomain = $from.Split("@")[-1]
    $returnPathDomain = $returnPath.Split("@")[-1]

    # Domain checks
    if ($fromDomain -ne $returnPathDomain) {
        $spamScore++
        $notes += "Mismatch between 'From' domain ($fromDomain) and 'Return-Path' domain ($returnPathDomain)."
    } elseif ($from -ne $returnPath) {
        $spamScore++
        $notes += "'From' address ($from) and 'Return-Path' address ($returnPath) differ even though domains match."
    }

    # Subject keywords
    if ($subject -match "\b(urgent|verify|account|suspend|important|alert|update)\b") {
        $spamScore++
        $notes += "Suspicious keyword in subject: $subject"
    }

    # SPF, DKIM, DMARC
    $spf = [regex]::Match($headers, "Received-SPF:\s*(\w+)").Groups[1].Value
    $dkim = [regex]::Match($headers, "Authentication-Results:.*dkim=(\w+)").Groups[1].Value
    $dmarc = [regex]::Match($headers, "Authentication-Results:.*dmarc=(\w+)").Groups[1].Value

    if ($spf -and $spf -ne "pass") {
        $spamScore++
        $notes += "SPF check failed: $spf"
    }
    if ($dkim -and $dkim -ne "pass") {
        $spamScore++
        $notes += "DKIM check failed: $dkim"
    }
    if ($dmarc -and $dmarc -ne "pass") {
        $spamScore++
        $notes += "DMARC check failed: $dmarc"
    }

    # Output
    $outputBox.AppendText("Bradley's Email Header Analyzer Tool v0.2`n")
    $outputBox.AppendText("------------------------------------------`n")
    $outputBox.SelectionColor = 'Cyan'
    $outputBox.AppendText("From: $from`nReturn-Path: $returnPath`nSubject: $subject`n")
    $outputBox.AppendText("SPF: $spf | DKIM: $dkim | DMARC: $dmarc`n")
    $outputBox.SelectionColor = 'White'
    $outputBox.AppendText("------------------------------------------`n")

    if ($spamScore -gt 0) {
        $outputBox.SelectionColor = 'Red'
        $outputBox.AppendText("⚠ Potential Spam Detected! Spam Score: $spamScore`n")
        $outputBox.AppendText("Reasons:`n")
        $notes | ForEach-Object { $outputBox.AppendText("- $_`n") }
    } else {
        $outputBox.SelectionColor = 'Lime'
        $outputBox.AppendText("✅ No spam indicators found.`n")
    }

    $outputBox.SelectionColor = 'White'
    $outputBox.AppendText("------------------------------------------`n")
})

# Show form
[void]$form.ShowDialog()
