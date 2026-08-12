import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { App } from "./App";

// xterm probes the canvas at import time, which jsdom cannot provide; the
// test only exercises the onboarding surface, so xterm is stubbed.
vi.mock("@xterm/xterm", () => ({
  Terminal: class {
    loadAddon() {}
    open() {}
    write() {}
    dispose() {}
    onData() {
      return { dispose() {} };
    }
    onResize() {
      return { dispose() {} };
    }
  },
}));

vi.mock("@xterm/addon-fit", () => ({
  FitAddon: class {
    fit() {}
    proposeDimensions() {
      return { cols: 80, rows: 24 };
    }
  },
}));

describe("Admin onboarding", () => {
  it("starts with secure enrollment call to action", () => {
    render(<App />);
    expect(screen.getByText("No server profile")).toBeTruthy();
    expect(
      screen.getByRole("button", { name: "Enroll this Admin" }),
    ).toBeTruthy();
  });
});
