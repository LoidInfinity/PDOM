using System.Windows;
using System.Windows.Controls;
using Keep.App.ViewModels;

namespace Keep.App.Views;

public partial class RulesPage : UserControl
{
    public RulesPage()
    {
        InitializeComponent();
    }

    private void OnFilterChecked(object sender, RoutedEventArgs e)
    {
        if (DataContext is MainViewModel viewModel && sender is RadioButton { Tag: string filter })
        {
            viewModel.Filter = filter;
        }
    }

    private void OnToggleRule(object sender, RoutedEventArgs e)
    {
        (DataContext as MainViewModel)?.SaveBaseline();
    }
}
