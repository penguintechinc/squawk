"""
Screenshot Tool for Manager UI Documentation
Captures screenshots of the Manager web interface for README documentation.
"""
from playwright.async_api import async_playwright
import os
import asyncio
import argparse
from datetime import datetime


async def capture_manager_screenshots(
    base_url: str = "http://localhost:3000",
    output_dir: str = "./docs/screenshots",
    username: str = "admin",
    password: str = "admin123"
):
    """
    Capture screenshots of Manager UI for documentation.

    Args:
        base_url: Manager frontend URL
        output_dir: Directory to save screenshots
        username: Login username
        password: Login password
    """
    os.makedirs(output_dir, exist_ok=True)

    pages_to_capture = [
        {"path": "/", "name": "dashboard", "description": "Main Dashboard"},
        {"path": "/dns-servers", "name": "dns-servers", "description": "DNS Server Fleet"},
        {"path": "/users", "name": "users", "description": "User Management"},
        {"path": "/teams", "name": "teams", "description": "Team Management"},
        {"path": "/zones", "name": "zones", "description": "DNS Zone Management"},
        {"path": "/tokens", "name": "tokens", "description": "API Token Management"},
        {"path": "/analytics", "name": "analytics", "description": "Analytics Dashboard"},
        {"path": "/ioc-feeds", "name": "ioc-feeds", "description": "IOC Feed Management"},
        {"path": "/settings", "name": "settings", "description": "Settings"},
    ]

    print(f"Starting screenshot capture from {base_url}")
    print(f"Output directory: {output_dir}")
    print("-" * 60)

    async with async_playwright() as p:
        # Launch browser
        browser = await p.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ],
        )

        # Create context with viewport
        context = await browser.new_context(
            viewport={"width": 1920, "height": 1080},
            ignore_https_errors=True,
        )

        # Create page
        page = await context.new_page()

        try:
            # Navigate to login page
            print("Logging in...")
            await page.goto(f"{base_url}/login", wait_until="load", timeout=30000)

            # Fill login form
            await page.fill('input[name="username"]', username)
            await page.fill('input[name="password"]', password)
            await page.click('button[type="submit"]')

            # Wait for navigation to dashboard
            await page.wait_for_url(f"{base_url}/", timeout=10000)
            print("Login successful")

        except Exception as e:
            print(f"Login failed: {e}")
            print("Skipping login, will try to capture pages directly")

        # Capture screenshots
        results = []
        for page_info in pages_to_capture:
            url = f"{base_url}{page_info['path']}"
            filename = f"{page_info['name']}.png"
            filepath = os.path.join(output_dir, filename)

            print(f"\nCapturing: {page_info['description']}")
            print(f"  URL: {url}")

            try:
                # Navigate to page
                await page.goto(url, wait_until="load", timeout=30000)

                # Wait for page to stabilize
                await page.wait_for_timeout(2000)

                # Take screenshot
                await page.screenshot(path=filepath, full_page=False)

                print(f"  Saved: {filepath}")

                results.append({
                    "name": page_info['name'],
                    "description": page_info['description'],
                    "path": filepath,
                    "success": True,
                })

            except Exception as e:
                print(f"  Failed: {e}")
                results.append({
                    "name": page_info['name'],
                    "description": page_info['description'],
                    "error": str(e),
                    "success": False,
                })

        await browser.close()

    # Print summary
    print("\n" + "=" * 60)
    print("Screenshot Capture Summary")
    print("=" * 60)

    successful = sum(1 for r in results if r['success'])
    failed = sum(1 for r in results if not r['success'])

    print(f"Total: {len(results)}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")

    if failed > 0:
        print("\nFailed captures:")
        for r in results:
            if not r['success']:
                print(f"  - {r['name']}: {r.get('error', 'Unknown error')}")

    return results


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Capture Manager UI screenshots")
    parser.add_argument(
        "--url",
        default="http://localhost:3000",
        help="Manager frontend URL (default: http://localhost:3000)"
    )
    parser.add_argument(
        "--output",
        default="./docs/screenshots",
        help="Output directory (default: ./docs/screenshots)"
    )
    parser.add_argument(
        "--username",
        default="admin",
        help="Login username (default: admin)"
    )
    parser.add_argument(
        "--password",
        default="admin123",
        help="Login password (default: admin123)"
    )

    args = parser.parse_args()

    # Run screenshot capture
    asyncio.run(capture_manager_screenshots(
        base_url=args.url,
        output_dir=args.output,
        username=args.username,
        password=args.password
    ))


if __name__ == "__main__":
    main()
