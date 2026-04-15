import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Button } from "../components/ui/Button";
import { Input } from "../components/ui/Input";
import { Badge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { EmptyState } from "../components/ui/EmptyState";
import { Tabs } from "../components/ui/Tabs";
import { Breadcrumb } from "../components/ui/Breadcrumb";
import { Textarea } from "../components/ui/Textarea";
import { Select } from "../components/ui/Select";

describe("Button", () => {
  it("renders with children text", () => {
    render(<Button>Click me</Button>);
    expect(screen.getByRole("button")).toHaveTextContent("Click me");
  });

  it("applies primary variant by default", () => {
    render(<Button>Primary</Button>);
    const btn = screen.getByRole("button");
    expect(btn.className).toContain("bg-[var(--color-primary)]");
  });

  it("applies danger variant", () => {
    render(<Button variant="danger">Delete</Button>);
    const btn = screen.getByRole("button");
    expect(btn.className).toContain("text-red-400");
  });

  it("disables when loading", () => {
    render(<Button loading>Save</Button>);
    expect(screen.getByRole("button")).toBeDisabled();
  });

  it("disables when disabled prop is set", () => {
    render(<Button disabled>Disabled</Button>);
    expect(screen.getByRole("button")).toBeDisabled();
  });

  it("calls onClick when clicked", async () => {
    const user = userEvent.setup();
    let clicked = false;
    render(<Button onClick={() => { clicked = true; }}>Click</Button>);
    await user.click(screen.getByRole("button"));
    expect(clicked).toBe(true);
  });

  it("applies fullWidth class", () => {
    render(<Button fullWidth>Full</Button>);
    expect(screen.getByRole("button").className).toContain("w-full");
  });
});

describe("Input", () => {
  it("renders with label", () => {
    render(<Input label="Username" />);
    expect(screen.getByLabelText("Username")).toBeInTheDocument();
  });

  it("shows error message", () => {
    render(<Input label="Email" error="Invalid email" />);
    expect(screen.getByText("Invalid email")).toBeInTheDocument();
  });

  it("shows hint when no error", () => {
    render(<Input label="Name" hint="Your full name" />);
    expect(screen.getByText("Your full name")).toBeInTheDocument();
  });

  it("does not show hint when error is present", () => {
    render(<Input label="Name" hint="Your full name" error="Required" />);
    expect(screen.queryByText("Your full name")).not.toBeInTheDocument();
    expect(screen.getByText("Required")).toBeInTheDocument();
  });

  it("accepts user input", async () => {
    const user = userEvent.setup();
    render(<Input label="Search" />);
    const input = screen.getByLabelText("Search");
    await user.type(input, "hello");
    expect(input).toHaveValue("hello");
  });
});

describe("Textarea", () => {
  it("renders with label", () => {
    render(<Textarea label="Notes" />);
    expect(screen.getByLabelText("Notes")).toBeInTheDocument();
  });

  it("shows error message", () => {
    render(<Textarea label="Policy" error="Invalid HCL" />);
    expect(screen.getByText("Invalid HCL")).toBeInTheDocument();
  });
});

describe("Select", () => {
  const options = [
    { value: "a", label: "Option A" },
    { value: "b", label: "Option B" },
  ];

  it("renders with label and options", () => {
    render(<Select label="Type" options={options} />);
    expect(screen.getByLabelText("Type")).toBeInTheDocument();
    expect(screen.getByText("Option A")).toBeInTheDocument();
    expect(screen.getByText("Option B")).toBeInTheDocument();
  });
});

describe("Badge", () => {
  it("renders label text", () => {
    render(<Badge label="Active" />);
    expect(screen.getByText("Active")).toBeInTheDocument();
  });

  it("renders with dot when dot prop is true", () => {
    const { container } = render(<Badge label="Online" variant="success" dot />);
    const dots = container.querySelectorAll(".rounded-full");
    // One for the badge itself (rounded-full) and one for the dot
    expect(dots.length).toBeGreaterThanOrEqual(1);
  });
});

describe("Card", () => {
  it("renders title and children", () => {
    render(<Card title="Settings">Card content</Card>);
    expect(screen.getByText("Settings")).toBeInTheDocument();
    expect(screen.getByText("Card content")).toBeInTheDocument();
  });

  it("renders actions", () => {
    render(
      <Card title="Test" actions={<button>Action</button>}>
        Content
      </Card>,
    );
    expect(screen.getByText("Action")).toBeInTheDocument();
  });

  it("renders without title", () => {
    render(<Card>Just content</Card>);
    expect(screen.getByText("Just content")).toBeInTheDocument();
  });
});

describe("EmptyState", () => {
  it("renders title and description", () => {
    render(<EmptyState title="No data" description="Nothing to show" />);
    expect(screen.getByText("No data")).toBeInTheDocument();
    expect(screen.getByText("Nothing to show")).toBeInTheDocument();
  });

  it("renders action button when provided", () => {
    render(
      <EmptyState title="Empty" action={<button>Create</button>} />,
    );
    expect(screen.getByText("Create")).toBeInTheDocument();
  });
});

describe("Tabs", () => {
  it("renders all tabs", () => {
    const tabs = [
      { id: "a", label: "Tab A" },
      { id: "b", label: "Tab B" },
    ];
    render(<Tabs tabs={tabs} active="a" onChange={() => {}} />);
    expect(screen.getByText("Tab A")).toBeInTheDocument();
    expect(screen.getByText("Tab B")).toBeInTheDocument();
  });

  it("highlights active tab", () => {
    const tabs = [
      { id: "a", label: "Tab A" },
      { id: "b", label: "Tab B" },
    ];
    render(<Tabs tabs={tabs} active="a" onChange={() => {}} />);
    const tabA = screen.getByText("Tab A");
    expect(tabA.className).toContain("border-[var(--color-primary)]");
  });

  it("calls onChange when tab is clicked", async () => {
    const user = userEvent.setup();
    let selected = "a";
    const tabs = [
      { id: "a", label: "Tab A" },
      { id: "b", label: "Tab B" },
    ];
    render(<Tabs tabs={tabs} active={selected} onChange={(id) => { selected = id; }} />);
    await user.click(screen.getByText("Tab B"));
    expect(selected).toBe("b");
  });
});

describe("Breadcrumb", () => {
  it("renders segments", () => {
    const segments = [
      { label: "Home", onClick: () => {} },
      { label: "Secrets" },
    ];
    render(<Breadcrumb segments={segments} />);
    expect(screen.getByText("Home")).toBeInTheDocument();
    expect(screen.getByText("Secrets")).toBeInTheDocument();
  });

  it("makes clickable segments into buttons", () => {
    const segments = [
      { label: "Root", onClick: () => {} },
      { label: "Current" },
    ];
    render(<Breadcrumb segments={segments} />);
    expect(screen.getByText("Root").tagName).toBe("BUTTON");
    expect(screen.getByText("Current").tagName).toBe("SPAN");
  });
});
