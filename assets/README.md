# stoop brand assets

The mark is a peregrine in its stoop: wings folded, head down, the yellow eye-ring on the one thing it is watching. The wordmark is Bodoni Moda Italic, outlined so no font is needed.

| File | Use it for |
|---|---|
| `stoop-logo-on-light.svg` | Mark and wordmark on a light background |
| `stoop-logo-on-dark.svg` | Mark and wordmark on a dark background |
| `stoop-logo.svg` | Follows the viewer's color scheme (`prefers-color-scheme`); only right where the background follows it too |
| `stoop-mark-on-light.svg`, `stoop-mark-on-dark.svg`, `stoop-mark.svg` | The falcon alone, same rules |
| `stoop-wordmark.svg` | The word alone, follows the color scheme |
| `stoop-app.svg`, `stoop-app-512.png` | Square app mark on its own sky ground; safe on any background |
| `favicon-32.png`, `apple-touch-icon.png` | Browser and home-screen icons |
| `social-preview.png` | 1280x640 card for the repository's social preview and link unfurls |
| `readme-hero-light.jpg`, `readme-hero-dark.jpg` | README hero, daylight and blue hour. The dark one is a tonal grade of the light one (exposure about half, cold blue cast, a faint warm band at the horizon), not a separate scene |
| `demo-terminal-light.png`, `demo-terminal-dark.png` | README terminal capture, one theme each, rendered from the same template. The transcript is a captured run, with only cargo's progress lines cut |

In Markdown that renders on both themes, pair the light and dark files:

```html
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/stoop-logo-on-dark.svg">
  <img alt="stoop" src="assets/stoop-logo-on-light.svg" width="300">
</picture>
```

Colors, taken from the bird: malar black `#15181c`, barred-breast pale `#e9eef2`, slate `#4b5868`, morning sky `#eef2f5`, and cere yellow `#f0c419`, used only as a mark, never for text.
