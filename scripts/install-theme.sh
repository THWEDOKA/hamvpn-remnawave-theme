#!/bin/sh
set -eu

index=/opt/app/frontend/index.html

test -f "$index"
test -f /opt/app/frontend/hamvpn/hamvpn-theme.css
test -f /opt/app/frontend/hamvpn/hamvpn-mascot.png

if ! grep -q '/hamvpn/hamvpn-theme.css' "$index"; then
    sed -i 's#</head>#        <link rel="stylesheet" href="/hamvpn/hamvpn-theme.css" />\n    </head>#' "$index"
fi

sed -i 's#<title>Remnawave</title>#<title>HAMVPN · Remnawave</title>#' "$index"
sed -i 's|content="#161B23"|content="#10071c"|' "$index"
sed -i 's#content="Remnawave"#content="HAMVPN"#' "$index"

if ! grep -q 'hamvpn-source-link' "$index"; then
    sed -i 's#</body>#        <a class="hamvpn-source-link" href="https://github.com/THWEDOKA/hamvpn-remnawave-theme" target="_blank" rel="noopener noreferrer">Исходный код темы</a>\n    </body>#' "$index"
fi

grep -q '/hamvpn/hamvpn-theme.css' "$index"
grep -q 'hamvpn-source-link' "$index"
