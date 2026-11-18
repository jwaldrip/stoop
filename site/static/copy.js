// A copy button on every code block. In a transcript it copies only the
// commands (the lines after a "$" prompt, with their continuations), never the
// output; anywhere else it copies the whole block.
(() => {
  const commands = (pre) => {
    if (!pre.querySelector(".p")) return pre.textContent;
    const out = [];
    let continuing = false;
    for (const line of pre.textContent.split("\n")) {
      if (line.startsWith("$ ")) {
        out.push(line.slice(2));
        continuing = line.endsWith("\\");
      } else if (continuing) {
        out.push(line);
        continuing = line.endsWith("\\");
      }
    }
    return out.join("\n");
  };
  const init = () => {
    if (!navigator.clipboard) return;
    for (const pre of document.querySelectorAll("pre")) {
      const box = document.createElement("div");
      box.className = "code";
      pre.replaceWith(box);
      box.append(pre);
      const button = document.createElement("button");
      button.type = "button";
      button.className = "copy";
      button.textContent = "Copy";
      button.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(commands(pre));
          button.textContent = "Copied";
        } catch {
          button.textContent = "Select and copy";
        }
        setTimeout(() => { button.textContent = "Copy"; }, 1600);
      });
      box.append(button);
    }
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
