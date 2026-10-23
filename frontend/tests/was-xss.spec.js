import { expect, test } from '@playwright/test';

test('XSS payload is displayed as text and never executes', async ({ page }) => {
  await page.goto('/login');
  await page.getByRole('button', { name: /Administrator/ }).click();
  await page.getByRole('button', { name: 'Access SOC Intelligence Console' }).click();
  await page.waitForURL('**/admin-dash');
  await expect(page.getByText('Active Persona:')).toHaveCount(0);
  await page.goto('/was-lab');

  await page.getByRole('button', { name: /XSS Prevention/ }).click();
  const payload = "<script>document.body.dataset.wasXss='executed'</script>";
  await page.locator('textarea').fill(payload);
  await page.getByRole('button', { name: 'Test XSS Prevention' }).click();

  const rendered = page.getByTestId('xss-rendered-content');
  await expect(rendered).toHaveText(payload);
  await expect(rendered.locator('script')).toHaveCount(0);
  await expect(page.locator('body')).not.toHaveAttribute('data-was-xss', 'executed');

  const alertLink = page.getByRole('link', { name: /Open alert WAS-/ });
  await expect(alertLink).toHaveAttribute('href', /\/alerts\?alert_id=WAS-/);
  await alertLink.click();
  await expect(page.getByRole('heading', { name: /\[WAS-DEMO\] XSS Prevention:/ })).toBeVisible();
  await expect(page.getByRole('button', { name: /Escalate to Incident/ })).toBeVisible();
});
