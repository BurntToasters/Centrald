import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { App } from "./App";

describe("Admin onboarding", () => {
  it("starts with secure enrollment call to action", () => {
    render(<App />);
    expect(screen.getByText("No server profile")).toBeTruthy();
    expect(
      screen.getByRole("button", { name: "Enroll this Admin" }),
    ).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Terminal" })).toBeNull();
  });
});
